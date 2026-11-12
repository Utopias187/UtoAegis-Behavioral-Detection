using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UtoAegis.Infrastructure.Telemetry;

namespace UtoAegis.Telemetry.Tests;

[TestClass]
public sealed class TelemetryCollectorClientTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 11, 18, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public async Task SendAsync_SignsExactBatchAndReturnsAcknowledgement()
    {
        var key = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
        var record = CreateRecord();
        var handler = new CapturingHandler(record.Sequence, record.Hash);
        using var client = new TelemetryCollectorClient(
            new HttpClient(handler),
            new Uri("https://collector.example.test/v1/records?tenant=blue"),
            "endpoint-key-1",
            key,
            new FixedTimeProvider(Now));

        var acknowledgement = await client.SendAsync("monitor", [record]);

        Assert.AreEqual(record.Sequence, acknowledgement.AcceptedSequence);
        Assert.AreEqual("endpoint-key-1", handler.KeyId);
        Assert.AreEqual(
            Now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            handler.Timestamp);
        Assert.IsNotNull(handler.Nonce);
        Assert.IsNotNull(handler.Signature);
        using var document = JsonDocument.Parse(handler.Body!);
        Assert.AreEqual("monitor", document.RootElement.GetProperty("source").GetString());
        var bodyHash = Convert.ToHexString(SHA256.HashData(handler.Body!)).ToLowerInvariant();
        var signingInput = Encoding.UTF8.GetBytes(
            $"POST\n/v1/records?tenant=blue\n{handler.Timestamp}\n{handler.Nonce}\n{bodyHash}");
        var expected = Convert.ToBase64String(HMACSHA256.HashData(key, signingInput));
        Assert.AreEqual(expected, handler.Signature);
    }

    [TestMethod]
    public void Constructor_HttpCollector_IsRejected()
    {
        using var httpClient = new HttpClient(new CapturingHandler(1, new string('a', 64)));
        Assert.ThrowsExactly<ArgumentException>(() => new TelemetryCollectorClient(
            httpClient,
            new Uri("http://collector.example.test/v1/records"),
            "endpoint-key-1",
            new byte[32]));
    }

    private static SecurityTelemetryEnvelope CreateRecord()
    {
        using var document = JsonDocument.Parse("{\"status\":\"detected\"}");
        return new SecurityTelemetryEnvelope(
            1,
            7,
            Now,
            "monitor",
            "detection.response",
            "endpoint-001",
            "run-001",
            document.RootElement.Clone(),
            new string('b', 64),
            new string('c', 64));
    }

    private sealed class CapturingHandler(long sequence, string hash) : HttpMessageHandler
    {
        public byte[]? Body { get; private set; }

        public string? KeyId { get; private set; }

        public string? Timestamp { get; private set; }

        public string? Nonce { get; private set; }

        public string? Signature { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            KeyId = request.Headers.GetValues("X-UtoAegis-Key-Id").Single();
            Timestamp = request.Headers.GetValues("X-UtoAegis-Timestamp").Single();
            Nonce = request.Headers.GetValues("X-UtoAegis-Nonce").Single();
            Signature = request.Headers.GetValues("X-UtoAegis-Signature").Single();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new TelemetryCollectorAcknowledgement(sequence, hash))
            };
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
