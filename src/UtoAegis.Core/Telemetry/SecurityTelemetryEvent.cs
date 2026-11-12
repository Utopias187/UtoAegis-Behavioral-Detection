using System.Text;
using System.Text.Json;

namespace UtoAegis.Core.Telemetry;

public sealed record SecurityTelemetryEvent
{
    public const int MaximumIdentifierLength = 128;
    public const int MaximumPayloadBytes = 12 * 1024;

    public SecurityTelemetryEvent(
        DateTimeOffset timestampUtc,
        string source,
        string eventType,
        string deploymentId,
        string correlationId,
        string payloadJson)
    {
        TimestampUtc = timestampUtc.ToUniversalTime();
        Source = ValidateIdentifier(source, nameof(source));
        EventType = ValidateIdentifier(eventType, nameof(eventType));
        DeploymentId = ValidateIdentifier(deploymentId, nameof(deploymentId));
        CorrelationId = ValidateIdentifier(correlationId, nameof(correlationId));
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadJson);
        if (Encoding.UTF8.GetByteCount(payloadJson) > MaximumPayloadBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payloadJson),
                $"Telemetry payloads must not exceed {MaximumPayloadBytes} UTF-8 bytes.");
        }

        using var document = JsonDocument.Parse(payloadJson);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException(
                "The telemetry payload must be a JSON object.",
                nameof(payloadJson));
        }

        PayloadJson = document.RootElement.GetRawText();
    }

    public DateTimeOffset TimestampUtc { get; }

    public string Source { get; }

    public string EventType { get; }

    public string DeploymentId { get; }

    public string CorrelationId { get; }

    public string PayloadJson { get; }

    private static string ValidateIdentifier(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > MaximumIdentifierLength ||
            normalized.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_' and not ':'))
        {
            throw new ArgumentException(
                $"Telemetry identifiers must use 1 to {MaximumIdentifierLength} safe ASCII characters.",
                parameterName);
        }

        return normalized;
    }
}
