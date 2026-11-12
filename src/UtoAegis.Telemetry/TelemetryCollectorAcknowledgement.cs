namespace UtoAegis.Telemetry;

public sealed record TelemetryCollectorAcknowledgement(
    long AcceptedSequence,
    string AcceptedHash);
