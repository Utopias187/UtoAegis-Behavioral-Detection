using System.Net;
using UtoAegis.Core.Behavior;
using UtoAegis.Infrastructure.Behavior;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class WindowsBehaviorNormalizerTests
{
    private static readonly Guid Generation = Guid.Parse("b48ce264-1db9-4203-a8cb-6d624f254b5e");

    [TestMethod]
    public void CreatePathToken_IsStableAndDoesNotRetainRawPath()
    {
        const string path = @"C:\Users\Francisco\private.exe";

        var first = WindowsBehaviorNormalizer.CreatePathToken(path);
        var second = WindowsBehaviorNormalizer.CreatePathToken(path.ToLowerInvariant());

        Assert.AreEqual(first, second);
        StringAssert.StartsWith(first, "path-sha256:");
        Assert.IsFalse(first.Contains("Francisco", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Normalize_ProcessStart_ResolvesExactParentInstance()
    {
        var normalizer = new WindowsBehaviorNormalizer(Generation);
        Assert.IsTrue(normalizer.TryNormalize(Start(10, 100), out _));

        Assert.IsTrue(normalizer.TryNormalize(
            new WindowsProcessStartedRecord(
                11,
                200,
                10,
                100,
                @"C:\child.exe",
                null,
                BehaviorIntegrityClass.Medium),
            out var child));

        Assert.AreEqual(10, child!.RelatedProcess?.ProcessId);
        Assert.AreEqual(100L, child.RelatedProcess?.StartSequence);
    }

    [TestMethod]
    public void Normalize_ReusedProcessId_DoesNotResolveOldGenerationMarker()
    {
        var normalizer = new WindowsBehaviorNormalizer(Generation);
        Assert.IsTrue(normalizer.TryNormalize(Start(10, 100), out _));
        Assert.IsTrue(normalizer.TryNormalize(Start(10, 200), out _));

        Assert.IsTrue(normalizer.TryNormalize(
            new WindowsFileChangedRecord(10, 100, @"C:\old.txt", BehaviorOperation.Modified),
            out var oldEvent));
        Assert.IsTrue(normalizer.TryNormalize(
            new WindowsFileChangedRecord(10, 200, @"C:\new.txt", BehaviorOperation.Modified),
            out var newEvent));

        Assert.AreNotEqual(oldEvent!.Subject, newEvent!.Subject);
    }

    [TestMethod]
    public void Normalize_UnknownStoppedProcess_IsRejected()
    {
        var normalizer = new WindowsBehaviorNormalizer(Generation);

        Assert.IsFalse(normalizer.TryNormalize(
            new WindowsProcessStoppedRecord(10, 100, 0),
            out var draft));
        Assert.IsNull(draft);
    }

    [TestMethod]
    public void Normalize_FileChange_StoresOnlyPathToken()
    {
        var normalizer = StartedNormalizer();

        Assert.IsTrue(normalizer.TryNormalize(
            new WindowsFileChangedRecord(
                10,
                100,
                @"C:\Users\Francisco\document.txt",
                BehaviorOperation.Modified),
            out var draft));

        var payload = (FileChangedPayload)draft!.Payload;
        Assert.IsFalse(payload.Artifact.PathToken!.Contains("Francisco", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Normalize_RegistryChange_ClassifiesWithoutRetainingKey()
    {
        var normalizer = StartedNormalizer();

        Assert.IsTrue(normalizer.TryNormalize(
            new WindowsRegistryChangedRecord(
                10,
                100,
                @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Demo",
                BehaviorOperation.Modified),
            out var draft));

        var payload = (RegistryChangedPayload)draft!.Payload;
        Assert.AreEqual(BehaviorRegistryLocation.RunKey, payload.Location);
    }

    [TestMethod]
    public void Normalize_NetworkConnection_ClassifiesWithoutRetainingAddress()
    {
        var normalizer = StartedNormalizer();

        Assert.IsTrue(normalizer.TryNormalize(
            new WindowsNetworkConnectedRecord(
                10,
                100,
                BehaviorNetworkProtocol.Tcp,
                BehaviorNetworkDirection.Outbound,
                IPAddress.Parse("8.8.8.8"),
                443),
            out var draft));

        var payload = (NetworkConnectedPayload)draft!.Payload;
        Assert.AreEqual(BehaviorAddressScope.Public, payload.AddressScope);
        Assert.AreEqual(443, payload.DestinationPort);
    }

    [TestMethod]
    public void Normalize_ControlCharacterProviderPath_IsRejected()
    {
        var normalizer = StartedNormalizer();

        Assert.IsFalse(normalizer.TryNormalize(
            new WindowsImageLoadedRecord(
                10,
                100,
                "bad\npath.dll",
                null,
                BehaviorSignatureState.Unknown),
            out _));
    }

    [TestMethod]
    public void Normalize_InvalidProviderEnum_IsRejectedDuringIngestion()
    {
        var normalizer = StartedNormalizer();
        Assert.IsFalse(normalizer.TryNormalize(
            new WindowsNetworkConnectedRecord(
                10,
                100,
                (BehaviorNetworkProtocol)999,
                BehaviorNetworkDirection.Outbound,
                IPAddress.Loopback,
                443),
            out var draft));
        Assert.IsNull(draft);
    }

    private static WindowsBehaviorNormalizer StartedNormalizer()
    {
        var normalizer = new WindowsBehaviorNormalizer(Generation);
        Assert.IsTrue(normalizer.TryNormalize(Start(10, 100), out _));
        return normalizer;
    }

    private static WindowsProcessStartedRecord Start(int processId, long marker) => new(
        processId,
        marker,
        null,
        null,
        @"C:\Windows\System32\example.exe",
        null,
        BehaviorIntegrityClass.Medium);
}
