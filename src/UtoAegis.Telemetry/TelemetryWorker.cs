using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UtoAegis.Infrastructure.Telemetry;

namespace UtoAegis.Telemetry;

internal sealed class TelemetryWorker(
    TelemetryConfiguration configuration,
    TelemetryForwarderEngine engine,
    ILogger<TelemetryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TelemetryLog.Started(logger, configuration.Sources.Count);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var results = await engine.RunOnceAsync(stoppingToken);
                    foreach (var result in results.Where(result => result.DeliveredRecords > 0))
                    {
                        TelemetryLog.Delivered(
                            logger,
                            result.DeliveredRecords,
                            result.Source,
                            result.CheckpointSequence);
                    }
                }
                catch (Exception exception) when (
                    exception is TelemetryCollectorException or
                        SecurityTelemetryException or IOException)
                {
                    TelemetryLog.Failed(logger, exception);
                }

                await Task.Delay(configuration.PollInterval, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            TelemetryLog.Stopped(logger);
        }
    }
}
