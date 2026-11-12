using System.Text.Json;
using UtoAegis.Core.Telemetry;

namespace UtoAegis.Infrastructure.Telemetry;

public sealed class SecurityTelemetryWriter(
    SecurityTelemetrySpool spool,
    string source,
    string deploymentId,
    TimeProvider? timeProvider = null) : IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions =
        new(JsonSerializerDefaults.Web);

    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public ValueTask<SecurityTelemetryEnvelope> WriteAsync<TPayload>(
        string eventType,
        string correlationId,
        TPayload payload,
        CancellationToken cancellationToken = default) =>
        spool.AppendAsync(
            new SecurityTelemetryEvent(
                _timeProvider.GetUtcNow(),
                source,
                eventType,
                deploymentId,
                correlationId,
                JsonSerializer.Serialize(payload, SerializerOptions)),
            cancellationToken);

    public void Dispose() => spool.Dispose();
}
