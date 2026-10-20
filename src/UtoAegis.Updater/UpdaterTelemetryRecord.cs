namespace UtoAegis.Updater;

public sealed record UpdaterTelemetryRecord(
    DateTimeOffset TimestampUtc,
    string RunId,
    string DeploymentId,
    string RolloutRing,
    UpdaterTelemetryEvent Event,
    int Attempt,
    long HighestAcceptedSequence,
    long? CandidateSequence,
    string? CandidateVersion,
    string Message);
