using Microsoft.Extensions.Logging;

namespace UtoAegis.Telemetry;

internal static partial class TelemetryLog
{
    [LoggerMessage(
        EventId = 2100,
        Level = LogLevel.Information,
        Message = "UtoAegis telemetry forwarder started with {SourceCount} source(s).")]
    public static partial void Started(ILogger logger, int sourceCount);

    [LoggerMessage(
        EventId = 2101,
        Level = LogLevel.Information,
        Message = "Delivered {RecordCount} telemetry record(s) for {Source}; checkpoint={Checkpoint}.")]
    public static partial void Delivered(
        ILogger logger,
        int recordCount,
        string source,
        long checkpoint);

    [LoggerMessage(
        EventId = 2400,
        Level = LogLevel.Error,
        Message = "Telemetry delivery failed; durable checkpoints were not advanced.")]
    public static partial void Failed(ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 2102,
        Level = LogLevel.Information,
        Message = "UtoAegis telemetry forwarder stopped.")]
    public static partial void Stopped(ILogger logger);
}
