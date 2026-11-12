using System.Text.Json;

namespace UtoAegis.Infrastructure.Telemetry;

public sealed record SecurityTelemetryEnvelope(
    int SchemaVersion,
    long Sequence,
    DateTimeOffset TimestampUtc,
    string Source,
    string EventType,
    string DeploymentId,
    string CorrelationId,
    JsonElement Payload,
    string PreviousHash,
    string Hash);
