namespace UtoAegis.Infrastructure.Telemetry;

public sealed record SecurityTelemetryCheckpoint(long Sequence, string Hash)
{
    public static SecurityTelemetryCheckpoint Empty { get; } = new(0, new string('0', 64));
}
