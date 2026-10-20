namespace UtoAegis.Updater;

public sealed record UpdaterRunResult(
    UpdaterRunStatus Status,
    int Attempts,
    long? PreviousSequence,
    long Sequence,
    string? Version,
    int PrunedVersionCount);
