using Microsoft.Extensions.Logging;

namespace UtoAegis.Updater;

internal static partial class UpdaterLog
{
    [LoggerMessage(
        EventId = 1100,
        Level = LogLevel.Information,
        Message = "UtoAegis updater started for deployment {DeploymentId} in rollout ring {RolloutRing}.")]
    public static partial void Started(
        ILogger logger,
        string deploymentId,
        string rolloutRing);

    [LoggerMessage(
        EventId = 1101,
        Level = LogLevel.Information,
        Message = "Threat content sequence {Sequence} is already current after {Attempts} attempt(s).")]
    public static partial void Current(
        ILogger logger,
        long sequence,
        int attempts);

    [LoggerMessage(
        EventId = 1102,
        Level = LogLevel.Information,
        Message = "Activated threat content {Version} at sequence {Sequence} after {Attempts} attempt(s); pruned {PrunedVersions} version(s).")]
    public static partial void Activated(
        ILogger logger,
        string version,
        long sequence,
        int attempts,
        int prunedVersions);

    [LoggerMessage(
        EventId = 1400,
        Level = LogLevel.Error,
        Message = "The threat-intelligence update check failed; last-known-good content remains active.")]
    public static partial void Failed(ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 1103,
        Level = LogLevel.Information,
        Message = "UtoAegis updater stopped.")]
    public static partial void Stopped(ILogger logger);
}
