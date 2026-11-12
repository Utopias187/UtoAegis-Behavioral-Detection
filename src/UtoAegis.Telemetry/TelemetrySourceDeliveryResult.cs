namespace UtoAegis.Telemetry;

public sealed record TelemetrySourceDeliveryResult(
    string Source,
    int DeliveredRecords,
    long CheckpointSequence);
