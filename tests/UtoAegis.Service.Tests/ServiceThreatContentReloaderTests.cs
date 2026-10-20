using UtoAegis.Core.Scanning;
using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.Signatures;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service.Tests;

[TestClass]
public sealed class ServiceThreatContentReloaderTests
{
    [TestMethod]
    public async Task CheckAsync_NewVerifiedContentSwapsScannerGeneration()
    {
        var initial = CreateSnapshot(1, "one");
        var candidate = CreateSnapshot(2, "two");
        var source = new StubSource(candidate);
        using var reloader = new ServiceThreatContentReloader(
            source,
            new StubLease(initial),
            new StubScanner("initial"),
            (snapshot, _) => ValueTask.FromResult<IFileScanner>(
                new StubScanner(snapshot.Manifest.Version)));

        var result = await reloader.CheckAsync();
        var scan = await reloader.Scanner.ScanAsync("sample.bin");

        Assert.AreEqual(ThreatContentReloadStatus.Reloaded, result.Status);
        Assert.AreEqual("two", scan.Path);
        Assert.AreEqual(2L, reloader.Scanner.Generation);
        Assert.AreEqual(1L, reloader.SuccessfulReloadCount);
        Assert.AreEqual(2L, reloader.Health.Sequence);
    }

    [TestMethod]
    public async Task CheckAsync_InvalidCandidateKeepsLastKnownGoodScanner()
    {
        var initial = CreateSnapshot(1, "one");
        var source = new StubSource(CreateSnapshot(2, "two"));
        using var reloader = new ServiceThreatContentReloader(
            source,
            new StubLease(initial),
            new StubScanner("initial"),
            (_, _) => throw new SignatureRuleFileException("candidate rejected"));

        var first = await reloader.CheckAsync();
        var repeated = await reloader.CheckAsync();
        var scan = await reloader.Scanner.ScanAsync("sample.bin");

        Assert.AreEqual(ThreatContentReloadStatus.Rejected, first.Status);
        Assert.IsTrue(first.ShouldLog);
        Assert.IsFalse(repeated.ShouldLog);
        Assert.AreEqual("initial", scan.Path);
        Assert.AreEqual(1L, reloader.Scanner.Generation);
        Assert.AreEqual(2L, reloader.RejectedReloadCount);
        Assert.AreEqual(1L, reloader.Health.Sequence);
        Assert.IsTrue(source.LastLease!.IsDisposed);
    }

    [TestMethod]
    public async Task CheckAsync_UnchangedContentDoesNotBuildScanner()
    {
        var initial = CreateSnapshot(1, "one");
        var factoryCalls = 0;
        using var reloader = new ServiceThreatContentReloader(
            new StubSource(initial),
            new StubLease(initial),
            new StubScanner("initial"),
            (_, _) =>
            {
                factoryCalls++;
                return ValueTask.FromResult<IFileScanner>(new StubScanner("unused"));
            });

        var result = await reloader.CheckAsync();

        Assert.AreEqual(ThreatContentReloadStatus.Unchanged, result.Status);
        Assert.AreEqual(0, factoryCalls);
        Assert.AreEqual(1L, reloader.Scanner.Generation);
    }

    private static ThreatContentSnapshot CreateSnapshot(long sequence, string version)
    {
        var manifest = new ThreatUpdateManifest(
            sequence,
            version,
            "test-key",
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1),
            [
                new ThreatContentDescriptor(
                    ThreatContentKind.HashIndicators,
                    new string('a', 64),
                    1),
                new ThreatContentDescriptor(
                    ThreatContentKind.ByteSignatures,
                    new string('b', 64),
                    1)
            ]);
        return new ThreatContentSnapshot(
            manifest,
            version,
            $"{version}.db",
            $"{version}.jsonl");
    }

    private sealed class StubSource(ThreatContentSnapshot snapshot) :
        IServiceThreatContentSource
    {
        public StubLease? LastLease { get; private set; }

        public ValueTask<ThreatContentStoreStatus> GetStatusAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ThreatContentStoreStatus(
                true,
                snapshot.Manifest.Version,
                snapshot.Manifest.Sequence,
                null,
                null,
                snapshot.Manifest.Sequence));

        public ValueTask<IServiceThreatContentLease> GetActiveAsync(
            CancellationToken cancellationToken = default)
        {
            LastLease = new StubLease(snapshot);
            return ValueTask.FromResult<IServiceThreatContentLease>(LastLease);
        }
    }

    private sealed class StubLease(ThreatContentSnapshot snapshot) :
        IServiceThreatContentLease
    {
        public ThreatContentSnapshot Snapshot { get; } = snapshot;

        public bool IsDisposed { get; private set; }

        public void Dispose() => IsDisposed = true;
    }

    private sealed class StubScanner(string resultPath) : IFileScanner
    {
        public ValueTask<FileScanResult> ScanAsync(
            string path,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new FileScanResult(
                FileHashScanResult.Failure(
                    FileHashScanStatus.FileNotFound,
                    resultPath,
                    TimeSpan.Zero,
                    "test"),
                null,
                null));
    }
}
