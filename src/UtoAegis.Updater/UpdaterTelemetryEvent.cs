namespace UtoAegis.Updater;

public enum UpdaterTelemetryEvent
{
    CheckStarted = 0,
    RetryScheduled = 1,
    AlreadyCurrent = 2,
    UpdateActivated = 3,
    UpdateRejected = 4,
    UpdateFailed = 5,
    RetentionFailed = 6,
    RetentionDeferred = 7
}
