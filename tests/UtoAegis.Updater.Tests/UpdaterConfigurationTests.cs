using Microsoft.Extensions.Configuration;

namespace UtoAegis.Updater.Tests;

[TestClass]
public sealed class UpdaterConfigurationTests
{
    private static readonly string[] RevokedKeyIds = ["retired-key-1"];
    private string _testDirectory = null!;
    private string _baseDirectory = null!;
    private string _contentDirectory = null!;
    private string _downloadDirectory = null!;
    private string _telemetryDirectory = null!;
    private string _securityTelemetryDirectory = null!;
    private string _keyPath = null!;

    [TestInitialize]
    public void Initialize()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        _baseDirectory = Path.Combine(_testDirectory, "install");
        _contentDirectory = Path.Combine(_testDirectory, "content");
        _downloadDirectory = Path.Combine(_testDirectory, "downloads");
        _telemetryDirectory = Path.Combine(_testDirectory, "telemetry");
        _securityTelemetryDirectory = Path.Combine(_testDirectory, "security-telemetry");
        var policyDirectory = Path.Combine(_testDirectory, "policy");
        foreach (var directory in new[]
        {
            _baseDirectory,
            _contentDirectory,
            _downloadDirectory,
            _telemetryDirectory,
            _securityTelemetryDirectory,
            policyDirectory
        })
        {
            Directory.CreateDirectory(directory);
        }

        _keyPath = Path.Combine(policyDirectory, "release.public.pem");
        File.WriteAllText(_keyPath, "test public key placeholder");
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
    public void Load_ValidSettings_ResolvesSecurityAndRolloutPolicy()
    {
        var configuration = BuildConfiguration();

        var result = UpdaterConfiguration.Load(configuration, _baseDirectory);

        Assert.AreEqual("https://updates.example.test/stable/", result.ChannelBaseUri.AbsoluteUri);
        Assert.AreEqual(_contentDirectory, result.ContentStorePath);
        Assert.AreEqual(_downloadDirectory, result.DownloadPath);
        Assert.AreEqual(Path.Combine(_telemetryDirectory, "updates.jsonl"), result.TelemetryPath);
        Assert.AreEqual(_securityTelemetryDirectory, result.SecurityTelemetrySpoolPath);
        Assert.AreEqual(10_000, result.TelemetryMaximumRecords);
        Assert.AreEqual("endpoint-001", result.DeploymentId);
        Assert.AreEqual("pilot", result.RolloutRing);
        Assert.AreEqual(TimeSpan.FromMinutes(10), result.PollInterval);
        Assert.AreEqual(TimeSpan.FromSeconds(30), result.RequestTimeout);
        Assert.AreEqual(4, result.MaximumRetainedVersions);
        Assert.AreEqual(3, result.RetryPolicy.MaximumAttempts);
        Assert.AreEqual(TimeSpan.FromSeconds(2), result.RetryPolicy.InitialDelay);
        Assert.AreEqual(TimeSpan.FromSeconds(20), result.RetryPolicy.MaximumDelay);
        Assert.AreEqual(_keyPath, result.TrustedSigningKeyPaths["release-key-1"]);
        CollectionAssert.AreEqual(
            RevokedKeyIds,
            result.RevokedSigningKeyIds.ToArray());
    }

    [TestMethod]
    public void Load_HttpChannel_RejectsConfiguration()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegisUpdater:ChannelBaseUri"] = "http://updates.example.test/stable/"
        });

        Assert.ThrowsExactly<UpdaterConfigurationException>(() =>
            UpdaterConfiguration.Load(configuration, _baseDirectory));
    }

    [TestMethod]
    public void Load_AllKeysRevoked_RejectsConfiguration()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegisUpdater:SigningKeys:0:Status"] = "Revoked"
        });

        var exception = Assert.ThrowsExactly<UpdaterConfigurationException>(() =>
            UpdaterConfiguration.Load(configuration, _baseDirectory));

        StringAssert.Contains(exception.Message, "At least one");
    }

    [TestMethod]
    public void Load_KeyInsideWritableDirectory_RejectsConfiguration()
    {
        var unsafeKey = Path.Combine(_downloadDirectory, "unsafe.public.pem");
        File.WriteAllText(unsafeKey, "test public key placeholder");
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegisUpdater:SigningKeys:0:PublicKeyPath"] = unsafeKey
        });

        var exception = Assert.ThrowsExactly<UpdaterConfigurationException>(() =>
            UpdaterConfiguration.Load(configuration, _baseDirectory));

        StringAssert.Contains(exception.Message, "outside updater-writable");
    }

    [TestMethod]
    public void Load_NestedWritableDirectories_RejectsConfiguration()
    {
        var nested = Path.Combine(_contentDirectory, "downloads");
        Directory.CreateDirectory(nested);
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegisUpdater:DownloadPath"] = nested
        });

        Assert.ThrowsExactly<UpdaterConfigurationException>(() =>
            UpdaterConfiguration.Load(configuration, _baseDirectory));
    }

    [TestMethod]
    public void Load_InvalidRetryBounds_RejectsConfiguration()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegisUpdater:Retry:MaximumAttempts"] = "11"
        });

        Assert.ThrowsExactly<UpdaterConfigurationException>(() =>
            UpdaterConfiguration.Load(configuration, _baseDirectory));
    }

    [TestMethod]
    public void RetryPolicy_Backoff_DoublesAndCapsDelay()
    {
        var policy = new UpdaterRetryPolicy(
            maximumAttempts: 5,
            initialDelay: TimeSpan.FromSeconds(3),
            maximumDelay: TimeSpan.FromSeconds(10));

        Assert.AreEqual(TimeSpan.FromSeconds(3), policy.GetDelay(1));
        Assert.AreEqual(TimeSpan.FromSeconds(6), policy.GetDelay(2));
        Assert.AreEqual(TimeSpan.FromSeconds(10), policy.GetDelay(3));
        Assert.AreEqual(TimeSpan.FromSeconds(10), policy.GetDelay(4));
    }

    private IConfiguration BuildConfiguration(
        IReadOnlyDictionary<string, string?>? overrides = null)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["UtoAegisUpdater:ChannelBaseUri"] = "https://updates.example.test/stable/",
            ["UtoAegisUpdater:ContentStorePath"] = _contentDirectory,
            ["UtoAegisUpdater:DownloadPath"] = _downloadDirectory,
            ["UtoAegisUpdater:TelemetryPath"] = Path.Combine(
                _telemetryDirectory,
                "updates.jsonl"),
            ["UtoAegisUpdater:SecurityTelemetrySpoolPath"] = _securityTelemetryDirectory,
            ["UtoAegisUpdater:DeploymentId"] = "endpoint-001",
            ["UtoAegisUpdater:RolloutRing"] = "pilot",
            ["UtoAegisUpdater:PollIntervalSeconds"] = "600",
            ["UtoAegisUpdater:RequestTimeoutSeconds"] = "30",
            ["UtoAegisUpdater:MaximumRetainedVersions"] = "4",
            ["UtoAegisUpdater:Retry:MaximumAttempts"] = "3",
            ["UtoAegisUpdater:Retry:InitialDelaySeconds"] = "2",
            ["UtoAegisUpdater:Retry:MaximumDelaySeconds"] = "20",
            ["UtoAegisUpdater:SigningKeys:0:KeyId"] = "release-key-1",
            ["UtoAegisUpdater:SigningKeys:0:PublicKeyPath"] = _keyPath,
            ["UtoAegisUpdater:SigningKeys:0:Status"] = "Trusted",
            ["UtoAegisUpdater:SigningKeys:1:KeyId"] = "retired-key-1",
            ["UtoAegisUpdater:SigningKeys:1:PublicKeyPath"] = _keyPath,
            ["UtoAegisUpdater:SigningKeys:1:Status"] = "Revoked"
        };
        if (overrides is not null)
        {
            foreach (var entry in overrides)
            {
                values[entry.Key] = entry.Value;
            }
        }

        return new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
    }
}
