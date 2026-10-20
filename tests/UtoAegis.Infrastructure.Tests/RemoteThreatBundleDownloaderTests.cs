using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class RemoteThreatBundleDownloaderTests
{
    private static readonly string[] AllBundleFiles =
        ["manifest.json", "manifest.sig", "indicators.jsonl", "signatures.jsonl"];
    private static readonly string[] MetadataFiles = ["manifest.json", "manifest.sig"];
    private static readonly string[] MetadataAndIndicatorFiles =
        ["manifest.json", "manifest.sig", "indicators.jsonl"];
    private static readonly DateTimeOffset Now =
        new(2026, 10, 20, 6, 0, 0, TimeSpan.Zero);

    private string _testDirectory = null!;
    private ECDsa _signingKey = null!;

    [TestInitialize]
    public void Initialize()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDirectory);
        _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
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
    public async Task DownloadAsync_ValidBundle_AuthenticatesBeforeDownloadingPayloads()
    {
        var files = CreateBundleFiles();
        var handler = new BundleHandler(files);
        var downloader = CreateDownloader(handler);
        var root = Path.Combine(_testDirectory, "downloads");

        string bundlePath;
        using (var bundle = await downloader.DownloadAsync(
            new Uri("https://updates.example.test/stable/"),
            root,
            highestAcceptedSequence: 6))
        {
            bundlePath = bundle.BundleDirectory;
            Assert.AreEqual(7L, bundle.Manifest.Sequence);
            CollectionAssert.AreEqual(
                AllBundleFiles,
                handler.RequestedFiles.ToArray());
            CollectionAssert.AreEquivalent(
                files.Keys.ToArray(),
                Directory.GetFiles(bundle.BundleDirectory)
                    .Select(Path.GetFileName)
                    .ToArray());
        }

        Assert.IsFalse(Directory.Exists(bundlePath));
    }

    [TestMethod]
    public async Task DownloadAsync_InvalidSignature_DoesNotRequestPayloadsAndCleansStaging()
    {
        var files = CreateBundleFiles();
        files[SignedThreatBundleVerifier.SignatureFileName] =
            Encoding.UTF8.GetBytes(Convert.ToBase64String(new byte[64]));
        var handler = new BundleHandler(files);
        var downloader = CreateDownloader(handler);
        var root = Path.Combine(_testDirectory, "downloads");

        await Assert.ThrowsExactlyAsync<ThreatUpdateException>(async () =>
            await downloader.DownloadAsync(
                new Uri("https://updates.example.test/stable/"),
                root,
                highestAcceptedSequence: 6));

        CollectionAssert.AreEqual(
            MetadataFiles,
            handler.RequestedFiles.ToArray());
        Assert.HasCount(0, Directory.GetFileSystemEntries(root));
    }

    [TestMethod]
    public async Task DownloadAsync_ServerFailure_ReportsTransientFailure()
    {
        var handler = new BundleHandler(
            CreateBundleFiles(),
            failureStatus: HttpStatusCode.ServiceUnavailable);
        var downloader = CreateDownloader(handler);
        var root = Path.Combine(_testDirectory, "downloads");

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateDownloadException>(async () =>
            await downloader.DownloadAsync(
                new Uri("https://updates.example.test/stable/"),
                root,
                highestAcceptedSequence: 6));

        Assert.IsTrue(exception.IsTransient);
        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, exception.StatusCode);
        Assert.HasCount(0, Directory.GetFileSystemEntries(root));
    }

    [TestMethod]
    public async Task DownloadAsync_PayloadLengthMismatch_IsPermanentAndCleansStaging()
    {
        var files = CreateBundleFiles();
        files["indicators.jsonl"] = [.. files["indicators.jsonl"], (byte)' '];
        var handler = new BundleHandler(files);
        var downloader = CreateDownloader(handler);
        var root = Path.Combine(_testDirectory, "downloads");

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateDownloadException>(async () =>
            await downloader.DownloadAsync(
                new Uri("https://updates.example.test/stable/"),
                root,
                highestAcceptedSequence: 6));

        Assert.IsFalse(exception.IsTransient);
        CollectionAssert.AreEqual(
            MetadataAndIndicatorFiles,
            handler.RequestedFiles.ToArray());
        Assert.HasCount(0, Directory.GetFileSystemEntries(root));
    }

    [TestMethod]
    public async Task DownloadAsync_ResponseFromDifferentUri_RejectsChannelCrossing()
    {
        var downloader = CreateDownloader(new CrossChannelHandler());
        var root = Path.Combine(_testDirectory, "downloads");

        var exception = await Assert.ThrowsExactlyAsync<ThreatUpdateDownloadException>(async () =>
            await downloader.DownloadAsync(
                new Uri("https://updates.example.test/stable/"),
                root,
                highestAcceptedSequence: 6));

        Assert.IsFalse(exception.IsTransient);
        StringAssert.Contains(exception.Message, "channel boundary");
        Assert.HasCount(0, Directory.GetFileSystemEntries(root));
    }

    [TestMethod]
    [DataRow("http://updates.example.test/stable/")]
    [DataRow("https://user:secret@updates.example.test/stable/")]
    [DataRow("https://updates.example.test/stable")]
    [DataRow("https://updates.example.test/stable/?channel=test")]
    public void ValidateChannelUri_UnsafeUri_Rejects(string uri)
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            RemoteThreatBundleDownloader.ValidateChannelUri(new Uri(uri)));
    }

    private RemoteThreatBundleDownloader CreateDownloader(HttpMessageHandler handler)
    {
        var key = new TrustedThreatSigningKey(
            "release-key-1",
            _signingKey.ExportSubjectPublicKeyInfoPem());
        var verifier = new SignedThreatBundleVerifier(
            new ThreatTrustStore([key]),
            timeProvider: new FixedTimeProvider(Now));
        return new RemoteThreatBundleDownloader(new HttpClient(handler), verifier);
    }

    private Dictionary<string, byte[]> CreateBundleFiles()
    {
        var indicators = Encoding.UTF8.GetBytes(
            "{\"sha256\":\"" + new string('a', 64) +
            "\",\"source\":\"test-feed\"}\n");
        var signatures = Encoding.UTF8.GetBytes(
            "{\"id\":\"test-rule\",\"name\":\"Test Rule\",\"source\":\"test-feed\",\"hexPattern\":\"4D5A900003000000\"}\n");
        var manifest = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            algorithm = ThreatUpdateManifest.SignatureAlgorithm,
            sequence = 7,
            version = "2026.10.20.1",
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

    private static object Content(string kind, byte[] payload) => new
    {
        kind,
        sha256 = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(),
        length = payload.LongLength
    };

    private sealed class BundleHandler(
        IReadOnlyDictionary<string, byte[]> files,
        HttpStatusCode? failureStatus = null) : HttpMessageHandler
    {
        public List<string> RequestedFiles { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var fileName = Path.GetFileName(request.RequestUri!.AbsolutePath);
            RequestedFiles.Add(fileName);
            if (failureStatus.HasValue)
            {
                return Task.FromResult(new HttpResponseMessage(failureStatus.Value)
                {
                    RequestMessage = request
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new ByteArrayContent(files[fileName])
            });
        }
    }

    private sealed class CrossChannelHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://other.example.test/manifest.json"),
                Content = new ByteArrayContent([1])
            });
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
