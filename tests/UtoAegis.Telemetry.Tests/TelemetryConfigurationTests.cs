using Microsoft.Extensions.Configuration;

namespace UtoAegis.Telemetry.Tests;

[TestClass]
public sealed class TelemetryConfigurationTests
{
    private string _root = null!;
    private string _install = null!;
    private string _state = null!;
    private string _spool = null!;
    private string _keyPath = null!;

    [TestInitialize]
    public void Initialize()
    {
        _root = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Telemetry.Tests",
            Guid.NewGuid().ToString("N"));
        _install = Path.Combine(_root, "install");
        _state = Path.Combine(_root, "state");
        _spool = Path.Combine(_root, "spool");
        var policy = Path.Combine(_root, "policy");
        foreach (var path in new[] { _install, _state, _spool, policy })
        {
            Directory.CreateDirectory(path);
        }

        _keyPath = Path.Combine(policy, "collector.key");
        File.WriteAllText(_keyPath, Convert.ToBase64String(new byte[32]));
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [TestMethod]
    public void Load_ValidConfiguration_ResolvesAuthenticatedBoundary()
    {
        var result = TelemetryConfiguration.Load(BuildConfiguration(), _install);

        Assert.AreEqual("collector.example.test", result.CollectorUri.Host);
        Assert.AreEqual("endpoint-key-1", result.AuthenticationKeyId);
        Assert.AreEqual(_keyPath, result.AuthenticationKeyPath);
        Assert.AreEqual(_state, result.StatePath);
        Assert.AreEqual(64, result.BatchSize);
        Assert.HasCount(1, result.Sources);
        Assert.AreEqual(_spool, result.Sources[0].SpoolPath);
        Assert.HasCount(32, TelemetryConfiguration.LoadAuthenticationKey(_keyPath));
    }

    [TestMethod]
    public void Load_HttpCollector_IsRejected()
    {
        var exception = Assert.ThrowsExactly<TelemetryConfigurationException>(() =>
            TelemetryConfiguration.Load(
                BuildConfiguration(new Dictionary<string, string?>
                {
                    ["UtoAegisTelemetry:CollectorUri"] =
                        "http://collector.example.test/v1/records"
                }),
                _install));

        StringAssert.Contains(exception.Message, "HTTPS");
    }

    [TestMethod]
    public void Load_StateNestedUnderSource_IsRejected()
    {
        var nested = Path.Combine(_spool, "state");
        Directory.CreateDirectory(nested);

        var exception = Assert.ThrowsExactly<TelemetryConfigurationException>(() =>
            TelemetryConfiguration.Load(
                BuildConfiguration(new Dictionary<string, string?>
                {
                    ["UtoAegisTelemetry:StatePath"] = nested
                }),
                _install));

        StringAssert.Contains(exception.Message, "non-nested");
    }

    private IConfiguration BuildConfiguration(
        IReadOnlyDictionary<string, string?>? overrides = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["UtoAegisTelemetry:CollectorUri"] =
                "https://collector.example.test/v1/records",
            ["UtoAegisTelemetry:AuthenticationKeyId"] = "endpoint-key-1",
            ["UtoAegisTelemetry:AuthenticationKeyPath"] = _keyPath,
            ["UtoAegisTelemetry:StatePath"] = _state,
            ["UtoAegisTelemetry:BatchSize"] = "64",
            ["UtoAegisTelemetry:PollIntervalSeconds"] = "15",
            ["UtoAegisTelemetry:RequestTimeoutSeconds"] = "20",
            ["UtoAegisTelemetry:Sources:0:Name"] = "monitor",
            ["UtoAegisTelemetry:Sources:0:SpoolPath"] = _spool
        };
        if (overrides is not null)
        {
            foreach (var entry in overrides)
            {
                values[entry.Key] = entry.Value;
            }
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }
}
