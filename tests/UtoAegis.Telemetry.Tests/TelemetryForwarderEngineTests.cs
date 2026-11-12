using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using UtoAegis.Core.Telemetry;
using UtoAegis.Infrastructure.Telemetry;

namespace UtoAegis.Telemetry.Tests;

[TestClass]
public sealed class TelemetryForwarderEngineTests
{
    private string _root = null!;
    private string _install = null!;
    private string _state = null!;
    private string _spoolPath = null!;
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
        _spoolPath = Path.Combine(_root, "spool");
        var policy = Path.Combine(_root, "policy");
        foreach (var path in new[] { _install, _state, _spoolPath, policy })
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
    public async Task RunOnceAsync_AcceptedBatch_AdvancesCheckpointAndDoesNotResend()
    {
        using (var spool = new SecurityTelemetrySpool(_spoolPath))
        {
            await spool.AppendAsync(CreateEvent("health", "one"));
            await spool.AppendAsync(CreateEvent("detection.response", "two"));
        }

        var handler = new AcknowledgingHandler(mismatch: false);
        using var collector = CreateEngine(handler, out var engine);

        var first = await engine.RunOnceAsync();
        var second = await engine.RunOnceAsync();
        using var checkpointStore = new SecurityTelemetryCheckpointStore(
            Path.Combine(_state, "monitor.checkpoint.json"));
        var checkpoint = await checkpointStore.LoadAsync();

        Assert.AreEqual(2, first[0].DeliveredRecords);
        Assert.AreEqual(0, second[0].DeliveredRecords);
        Assert.AreEqual(2L, checkpoint.Sequence);
        Assert.AreEqual(1, handler.CallCount);
    }

    [TestMethod]
    public async Task RunOnceAsync_MismatchedAcknowledgement_DoesNotAdvanceCheckpoint()
    {
        using (var spool = new SecurityTelemetrySpool(_spoolPath))
        {
            await spool.AppendAsync(CreateEvent("health", "one"));
        }

        using var collector = CreateEngine(
            new AcknowledgingHandler(mismatch: true),
            out var engine);

        await Assert.ThrowsExactlyAsync<TelemetryCollectorException>(
            () => engine.RunOnceAsync().AsTask());
        using var checkpointStore = new SecurityTelemetryCheckpointStore(
            Path.Combine(_state, "monitor.checkpoint.json"));
        Assert.AreEqual(SecurityTelemetryCheckpoint.Empty, await checkpointStore.LoadAsync());
    }

    private TelemetryCollectorClient CreateEngine(
        HttpMessageHandler handler,
        out TelemetryForwarderEngine engine)
    {
        var configuration = TelemetryConfiguration.Load(
            new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["UtoAegisTelemetry:CollectorUri"] =
                    "https://collector.example.test/v1/records",
                ["UtoAegisTelemetry:AuthenticationKeyId"] = "endpoint-key-1",
                ["UtoAegisTelemetry:AuthenticationKeyPath"] = _keyPath,
                ["UtoAegisTelemetry:StatePath"] = _state,
                ["UtoAegisTelemetry:BatchSize"] = "128",
                ["UtoAegisTelemetry:Sources:0:Name"] = "monitor",
                ["UtoAegisTelemetry:Sources:0:SpoolPath"] = _spoolPath
            }).Build(),
            _install);
        var collector = new TelemetryCollectorClient(
            new HttpClient(handler),
            configuration.CollectorUri,
            configuration.AuthenticationKeyId,
            new byte[32]);
        engine = new TelemetryForwarderEngine(configuration, collector);
        return collector;
    }

    private static SecurityTelemetryEvent CreateEvent(string eventType, string value) =>
        new(
            new DateTimeOffset(2026, 11, 11, 18, 0, 0, TimeSpan.Zero),
            "monitor",
            eventType,
            "endpoint-001",
            $"run-{value}",
            JsonSerializer.Serialize(new { value }));

    private sealed class AcknowledgingHandler(bool mismatch) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            var bytes = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            using var document = JsonDocument.Parse(bytes);
            var records = document.RootElement.GetProperty("records");
            var last = records[records.GetArrayLength() - 1];
            var sequence = last.GetProperty("sequence").GetInt64();
            var hash = last.GetProperty("hash").GetString()!;
            if (mismatch)
            {
                hash = new string(hash[0] == 'a' ? 'b' : 'a', 64);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(
                    new TelemetryCollectorAcknowledgement(sequence, hash))
            };
        }
    }
}
