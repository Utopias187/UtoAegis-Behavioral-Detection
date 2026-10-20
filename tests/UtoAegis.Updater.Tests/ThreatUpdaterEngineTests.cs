using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Updater.Tests;

[TestClass]
public sealed class ThreatUpdaterEngineTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 10, 20, 7, 0, 0, TimeSpan.Zero);
    private static readonly string[] ActivatedEvents = ["checkStarted", "updateActivated"];
    private static readonly string[] CurrentEvents = ["checkStarted", "alreadyCurrent"];
    private static readonly string[] PinnedEvents =
        ["checkStarted", "retentionDeferred", "updateActivated"];
    private static readonly string[] MetadataFiles = ["manifest.json", "manifest.sig"];
    private static readonly string[] ExhaustedEvents =
        ["checkStarted", "retryScheduled", "retryScheduled", "updateFailed"];
    private static readonly TimeSpan[] RetryDelays =
        [TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4)];

    private string _testDirectory = null!;
    private string _contentDirectory = null!;
    private string _downloadDirectory = null!;
    private string _telemetryDirectory = null!;
    private string _telemetryPath = null!;
    private string _keyPath = null!;
    private ECDsa _signingKey = null!;

    [TestInitialize]
    public void Initialize()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        _contentDirectory = Path.Combine(_testDirectory, "content");
        _downloadDirectory = Path.Combine(_testDirectory, "downloads");
        _telemetryDirectory = Path.Combine(_testDirectory, "telemetry");
        var installDirectory = Path.Combine(_testDirectory, "install");
        var policyDirectory = Path.Combine(_testDirectory, "policy");
        foreach (var directory in new[]
        {
            _contentDirectory,
            _downloadDirectory,
            _telemetryDirectory,
            installDirectory,
            policyDirectory
        })
        {
            Directory.CreateDirectory(directory);
        }

        _telemetryPath = Path.Combine(_telemetryDirectory, "updates.jsonl");
        _keyPath = Path.Combine(policyDirectory, "release.public.pem");
        _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(_keyPath, _signingKey.ExportSubjectPublicKeyInfoPem());
    }

    [TestCleanup]
    public void Cleanup()
    {
        _signingKey.Dispose();
        if (Directory.Exists(_testDirectory))
        {
            Directory.Delete(_testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task RunOnceAsync_NewSignedBundle_ActivatesAndEmitsRolloutTelemetry()
    {
        var files = CreateBundleFiles(sequence: 7, hashCharacter: 'a');
        var handler = new BundleHandler(files);
        var configuration = CreateConfiguration();
        var engine = CreateEngine(
            configuration,
            new RemoteThreatBundleDownloader(
                new HttpClient(handler),
                CreateVerifier()),
            out var store);

        var result = await engine.RunOnceAsync();
        var status = await store.GetStatusAsync();

        Assert.AreEqual(UpdaterRunStatus.Activated, result.Status);
        Assert.AreEqual(1, result.Attempts);
        Assert.AreEqual(7L, result.Sequence);
        Assert.AreEqual(7L, status.ActiveSequence);
        CollectionAssert.AreEqual(ActivatedEvents, ReadTelemetryEvents());
        var records = File.ReadAllLines(_telemetryPath);
        StringAssert.Contains(records[0], "\"deploymentId\":\"endpoint-001\"");
        StringAssert.Contains(records[0], "\"rolloutRing\":\"pilot\"");
    }

    [TestMethod]
    public async Task RunOnceAsync_CurrentSignedSequence_DownloadsOnlyMetadata()
    {
        var files = CreateBundleFiles(sequence: 7, hashCharacter: 'a');
        var configuration = CreateConfiguration();
        var store = CreateStore();
        var localBundle = Path.Combine(_testDirectory, "local-bundle");
        Directory.CreateDirectory(localBundle);
        foreach (var file in files)
        {
            await File.WriteAllBytesAsync(Path.Combine(localBundle, file.Key), file.Value);
        }

        await store.ApplyAsync(localBundle);
        var handler = new BundleHandler(files);
        var engine = new ThreatUpdaterEngine(
            configuration,
            new RemoteThreatBundleDownloader(new HttpClient(handler), CreateVerifier()),
            store,
            new UpdaterTelemetryWriter(_telemetryPath),
            new FixedTimeProvider(Now));

        var result = await engine.RunOnceAsync();

        Assert.AreEqual(UpdaterRunStatus.Current, result.Status);
        Assert.AreEqual(7L, result.Sequence);
        CollectionAssert.AreEqual(
            MetadataFiles,
            handler.RequestedFiles.ToArray());
        CollectionAssert.AreEqual(CurrentEvents, ReadTelemetryEvents());
    }

    [TestMethod]
    public async Task RunOnceAsync_PinnedGeneration_DefersRetentionAndReportsTelemetry()
    {
        var configuration = CreateConfiguration(maximumRetainedVersions: 2);
        var store = CreateStore();
        await ApplyBundleAsync(store, 7, 'a');
        using var lease = await store.GetActiveLeasedReadOnlyAsync();
        await ApplyBundleAsync(store, 8, 'b');
        await ApplyBundleAsync(store, 9, 'c');
        var handler = new BundleHandler(CreateBundleFiles(10, 'd'));
        var engine = new ThreatUpdaterEngine(
            configuration,
            new RemoteThreatBundleDownloader(new HttpClient(handler), CreateVerifier()),
            store,
            new UpdaterTelemetryWriter(_telemetryPath),
            new FixedTimeProvider(Now));

        var result = await engine.RunOnceAsync();

        Assert.AreEqual(UpdaterRunStatus.Activated, result.Status);
        Assert.IsTrue(Directory.Exists(lease.Snapshot.ContentDirectory));
        CollectionAssert.AreEqual(PinnedEvents, ReadTelemetryEvents());
    }

    [TestMethod]
    public async Task RunOnceAsync_TransientFailures_RetriesWithCappedBackoffThenFails()
    {
        var configuration = CreateConfiguration();
        var downloader = new FailingDownloader();
        var delays = new List<TimeSpan>();
        var engine = new ThreatUpdaterEngine(
            configuration,
            downloader,
            CreateStore(),
            new UpdaterTelemetryWriter(_telemetryPath),
            new FixedTimeProvider(Now),
            (delay, _) =>
            {
                delays.Add(delay);
                return Task.CompletedTask;
            });

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateDownloadException>(
            () => engine.RunOnceAsync().AsTask());

        Assert.IsTrue(exception.IsTransient);
        Assert.AreEqual(3, downloader.Attempts);
        CollectionAssert.AreEqual(RetryDelays, delays.ToArray());
        CollectionAssert.AreEqual(ExhaustedEvents, ReadTelemetryEvents());
    }

    private ThreatUpdaterEngine CreateEngine(
        UpdaterConfiguration configuration,
        IRemoteThreatBundleDownloader downloader,
        out ThreatContentStore store)
    {
        store = CreateStore();
        return new ThreatUpdaterEngine(
            configuration,
            downloader,
            store,
            new UpdaterTelemetryWriter(_telemetryPath),
            new FixedTimeProvider(Now));
    }

    private ThreatContentStore CreateStore() =>
        new(_contentDirectory, CreateVerifier());

    private SignedThreatBundleVerifier CreateVerifier()
    {
        var key = new TrustedThreatSigningKey(
            "release-key-1",
            _signingKey.ExportSubjectPublicKeyInfoPem());
        return new SignedThreatBundleVerifier(
            new ThreatTrustStore([key]),
            timeProvider: new FixedTimeProvider(Now));
    }

    private UpdaterConfiguration CreateConfiguration(int maximumRetainedVersions = 3)
    {
        var installDirectory = Path.Combine(_testDirectory, "install");
        var values = new Dictionary<string, string?>
        {
            ["UtoAegisUpdater:ChannelBaseUri"] = "https://updates.example.test/stable/",
            ["UtoAegisUpdater:ContentStorePath"] = _contentDirectory,
            ["UtoAegisUpdater:DownloadPath"] = _downloadDirectory,
            ["UtoAegisUpdater:TelemetryPath"] = _telemetryPath,
            ["UtoAegisUpdater:DeploymentId"] = "endpoint-001",
            ["UtoAegisUpdater:RolloutRing"] = "pilot",
            ["UtoAegisUpdater:PollIntervalSeconds"] = "600",
            ["UtoAegisUpdater:RequestTimeoutSeconds"] = "30",
            ["UtoAegisUpdater:MaximumRetainedVersions"] =
                maximumRetainedVersions.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["UtoAegisUpdater:Retry:MaximumAttempts"] = "3",
            ["UtoAegisUpdater:Retry:InitialDelaySeconds"] = "2",
            ["UtoAegisUpdater:Retry:MaximumDelaySeconds"] = "5",
            ["UtoAegisUpdater:SigningKeys:0:KeyId"] = "release-key-1",
            ["UtoAegisUpdater:SigningKeys:0:PublicKeyPath"] = _keyPath,
            ["UtoAegisUpdater:SigningKeys:0:Status"] = "Trusted"
        };
        var root = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        return UpdaterConfiguration.Load(root, installDirectory);
    }

    private async Task ApplyBundleAsync(
        ThreatContentStore store,
        long sequence,
        char hashCharacter)
    {
        var bundlePath = Path.Combine(_testDirectory, $"bundle-{sequence}");
        Directory.CreateDirectory(bundlePath);
        foreach (var file in CreateBundleFiles(sequence, hashCharacter))
        {
            await File.WriteAllBytesAsync(Path.Combine(bundlePath, file.Key), file.Value);
        }

        await store.ApplyAsync(bundlePath);
    }

    private Dictionary<string, byte[]> CreateBundleFiles(long sequence, char hashCharacter)
    {
        var indicators = Encoding.UTF8.GetBytes(
            "{\"sha256\":\"" + new string(hashCharacter, 64) +
            "\",\"source\":\"test-feed\"}\n");
        var signatures = Encoding.UTF8.GetBytes(
            "{\"id\":\"test-rule-" + sequence +
            "\",\"name\":\"Test Rule\",\"source\":\"test-feed\",\"hexPattern\":\"4D5A900003000000\"}\n");
        var manifest = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            algorithm = ThreatUpdateManifest.SignatureAlgorithm,
            sequence,
            version = $"2026.10.20.{sequence}",
            keyId = "release-key-1",
            publishedUtc = Now.AddMinutes(-5),
            expiresUtc = Now.AddDays(7),
            contents = new object[]
            {
                Content("hash-indicators", indicators),
                Content("byte-signatures", signatures)
            }
        });
        var signature = _signingKey.SignData(
            manifest,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        return new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["manifest.json"] = manifest,
            ["manifest.sig"] = Encoding.UTF8.GetBytes(Convert.ToBase64String(signature)),
            ["indicators.jsonl"] = indicators,
            ["signatures.jsonl"] = signatures
        };
    }

    private string[] ReadTelemetryEvents() => File.ReadAllLines(_telemetryPath)
        .Select(line =>
        {
            using var document = JsonDocument.Parse(line);
            return document.RootElement.GetProperty("event").GetString()!;
        })
        .ToArray();

    private static object Content(string kind, byte[] payload) => new
    {
        kind,
        sha256 = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(),
        length = payload.LongLength
    };

    private sealed class BundleHandler(IReadOnlyDictionary<string, byte[]> files)
        : HttpMessageHandler
    {
        public List<string> RequestedFiles { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var fileName = Path.GetFileName(request.RequestUri!.AbsolutePath);
            RequestedFiles.Add(fileName);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new ByteArrayContent(files[fileName])
            });
        }
    }

    private sealed class FailingDownloader : IRemoteThreatBundleDownloader
    {
        public int Attempts { get; private set; }

        public ValueTask<DownloadedThreatBundle> DownloadAsync(
            Uri channelBaseUri,
            string downloadRoot,
            long highestAcceptedSequence,
            CancellationToken cancellationToken = default)
        {
            Attempts++;
            throw new ThreatUpdateDownloadException(
                "The test server is unavailable.",
                isTransient: true,
                HttpStatusCode.ServiceUnavailable);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
