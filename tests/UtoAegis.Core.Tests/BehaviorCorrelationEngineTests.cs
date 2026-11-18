using System.Text.Json;
using UtoAegis.Core.Behavior;
using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class BehaviorCorrelationEngineTests
{
    private static readonly Guid Generation = Guid.Parse("1365a40f-80d6-4773-9871-c5d58d930800");
    private static readonly BehaviorProcessInstance Process = new(Generation, 42, 1);

    [TestMethod]
    public void Assess_CommonProcessStart_ReturnsNoKnownThreat()
    {
        var result = new BehaviorCorrelationEngine().Assess([Start(1, BehaviorIntegrityClass.Medium)]);

        Assert.AreEqual(RiskVerdict.NoKnownThreat, result.Verdict);
        Assert.AreEqual(0, result.Score);
        Assert.AreEqual(100, result.Confidence);
    }

    [TestMethod]
    public void Assess_SinglePersistenceChange_RemainsBelowReview()
    {
        var result = new BehaviorCorrelationEngine().Assess([Registry(1)]);

        Assert.AreEqual(8, result.Score);
        Assert.AreEqual(RiskVerdict.NoKnownThreat, result.Verdict);
    }

    [TestMethod]
    public void Assess_PersistenceAndPublicNetwork_ReturnsReview()
    {
        var result = new BehaviorCorrelationEngine().Assess([Registry(1), Network(2)]);

        Assert.AreEqual(38, result.Score);
        Assert.AreEqual(RiskVerdict.Review, result.Verdict);
    }

    [TestMethod]
    public void Assess_MultiCategorySequence_ReturnsMalicious()
    {
        var events = HighRiskEvents();

        var result = new BehaviorCorrelationEngine().Assess(events);

        Assert.AreEqual(100, result.Score);
        Assert.AreEqual(RiskVerdict.Malicious, result.Verdict);
        Assert.IsTrue(result.IsDetection);
    }

    [TestMethod]
    public void Assess_DegradedSequence_CannotAuthorizeMaliciousVerdict()
    {
        var events = HighRiskEvents().Append(Health(100, BehaviorProviderState.Degraded)).ToArray();

        var result = new BehaviorCorrelationEngine().Assess(events);

        Assert.AreEqual(100, result.Score);
        Assert.AreEqual(RiskVerdict.Review, result.Verdict);
        Assert.AreEqual(70, result.Confidence);
    }

    [TestMethod]
    public void Assess_UnreliableSequence_ReturnsInconclusive()
    {
        var result = new BehaviorCorrelationEngine().Assess(
            [Registry(1), Health(2, BehaviorProviderState.Unreliable)]);

        Assert.AreEqual(RiskVerdict.Inconclusive, result.Verdict);
        Assert.AreEqual(0, result.Confidence);
    }

    [TestMethod]
    public void Assess_InputOrder_IsDeterministic()
    {
        var events = HighRiskEvents();
        var engine = new BehaviorCorrelationEngine();

        var forward = engine.Assess(events);
        var reverse = engine.Assess(events.Reverse().ToArray());

        Assert.AreEqual(
            JsonSerializer.Serialize(forward),
            JsonSerializer.Serialize(reverse));
    }

    [TestMethod]
    public void Assess_MultipleProcessInstances_Throws()
    {
        var other = new BehaviorProcessInstance(Generation, 43, 2);

        Assert.ThrowsExactly<ArgumentException>(() => new BehaviorCorrelationEngine().Assess(
            [Start(1, BehaviorIntegrityClass.Medium), Start(2, BehaviorIntegrityClass.Medium, other)]));
    }

    [TestMethod]
    public void Assess_EventsOutsideWindow_AreExcluded()
    {
        var old = Registry(1);
        var recent = Network(2, seconds: 600);

        var result = new BehaviorCorrelationEngine().Assess([old, recent]);

        Assert.AreEqual(8, result.Score);
        Assert.AreEqual(1, result.EventCount);
    }

    private static BehaviorEvent[] HighRiskEvents()
    {
        var events = new List<BehaviorEvent>
        {
            Start(1, BehaviorIntegrityClass.High),
            Registry(2),
            Network(3),
            Image(4)
        };
        for (var index = 0; index < 40; index++)
        {
            events.Add(File(5 + index));
        }

        return events.ToArray();
    }

    private static BehaviorEvent Start(
        long sequence,
        BehaviorIntegrityClass integrity,
        BehaviorProcessInstance? process = null) => Event(
            sequence,
            BehaviorEventSource.Process,
            BehaviorEventKind.ProcessStarted,
            new ProcessStartedPayload(
                new BehaviorArtifactIdentity("path-sha256:" + new string('a', 64), null),
                integrity),
            process);

    private static BehaviorEvent Registry(long sequence) => Event(
        sequence,
        BehaviorEventSource.Registry,
        BehaviorEventKind.RegistryChanged,
        new RegistryChangedPayload(BehaviorRegistryLocation.RunKey, BehaviorOperation.Modified));

    private static BehaviorEvent Network(long sequence, int? seconds = null) => Event(
        sequence,
        BehaviorEventSource.Network,
        BehaviorEventKind.NetworkConnected,
        new NetworkConnectedPayload(
            BehaviorNetworkProtocol.Tcp,
            BehaviorNetworkDirection.Outbound,
            BehaviorAddressScope.Public,
            443),
        seconds: seconds);

    private static BehaviorEvent Image(long sequence) => Event(
        sequence,
        BehaviorEventSource.Image,
        BehaviorEventKind.ImageLoaded,
        new ImageLoadedPayload(
            new BehaviorArtifactIdentity("path-sha256:" + new string('b', 64), null),
            BehaviorSignatureState.Invalid));

    private static BehaviorEvent File(long sequence) => Event(
        sequence,
        BehaviorEventSource.FileSystem,
        BehaviorEventKind.FileChanged,
        new FileChangedPayload("path-sha256:" + new string('c', 64), BehaviorOperation.Modified));

    private static BehaviorEvent Health(long sequence, BehaviorProviderState state) => Event(
        sequence,
        BehaviorEventSource.Collector,
        BehaviorEventKind.ProviderHealth,
        new ProviderHealthPayload(BehaviorEventSource.Collector, state, 1),
        process: null);

    private static BehaviorEvent Event(
        long sequence,
        BehaviorEventSource source,
        BehaviorEventKind kind,
        BehaviorEventPayload payload,
        BehaviorProcessInstance? process = null,
        int? seconds = null) => new(
            GuidFrom(sequence),
            Generation,
            sequence,
            DateTimeOffset.UnixEpoch.AddSeconds(seconds ?? sequence),
            null,
            source,
            kind,
            kind == BehaviorEventKind.ProviderHealth ? null : process ?? Process,
            null,
            payload);

    private static Guid GuidFrom(long value)
    {
        Span<byte> bytes = stackalloc byte[16];
        BitConverter.TryWriteBytes(bytes, value);
        return new Guid(bytes);
    }
}
