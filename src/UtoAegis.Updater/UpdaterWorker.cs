using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Updater;

internal sealed class UpdaterWorker(
    UpdaterConfiguration configuration,
    ThreatUpdaterEngine engine,
    TimeProvider timeProvider,
    ILogger<UpdaterWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        UpdaterLog.Started(logger, configuration.DeploymentId, configuration.RolloutRing);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = await engine.RunOnceAsync(stoppingToken).ConfigureAwait(false);
                    if (result.Status == UpdaterRunStatus.Activated)
                    {
                        UpdaterLog.Activated(
                            logger,
                            result.Version!,
                            result.Sequence,
                            result.Attempts,
                            result.PrunedVersionCount);
                    }
                    else
                    {
                        UpdaterLog.Current(logger, result.Sequence, result.Attempts);
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception exception) when (
                    exception is ThreatUpdateDownloadException or
                        ThreatUpdateSequenceException or ThreatUpdateException or IOException)
                {
                    UpdaterLog.Failed(logger, exception);
                }

                await Task.Delay(
                    configuration.PollInterval,
                    timeProvider,
                    stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            UpdaterLog.Stopped(logger);
        }
    }
}
