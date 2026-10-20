using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Updater;

public sealed class ThreatUpdaterEngine
{
    private readonly UpdaterConfiguration _configuration;
    private readonly IRemoteThreatBundleDownloader _downloader;
    private readonly ThreatContentStore _contentStore;
    private readonly UpdaterTelemetryWriter _telemetry;
    private readonly TimeProvider _timeProvider;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public ThreatUpdaterEngine(
        UpdaterConfiguration configuration,
        IRemoteThreatBundleDownloader downloader,
        ThreatContentStore contentStore,
        UpdaterTelemetryWriter telemetry,
        TimeProvider? timeProvider = null)
        : this(
            configuration,
            downloader,
            contentStore,
            telemetry,
            timeProvider ?? TimeProvider.System,
            null)
    {
    }

    internal ThreatUpdaterEngine(
        UpdaterConfiguration configuration,
        IRemoteThreatBundleDownloader downloader,
        ThreatContentStore contentStore,
        UpdaterTelemetryWriter telemetry,
        TimeProvider timeProvider,
        Func<TimeSpan, CancellationToken, Task>? delay)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(downloader);
        ArgumentNullException.ThrowIfNull(contentStore);
        ArgumentNullException.ThrowIfNull(telemetry);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _configuration = configuration;
        _downloader = downloader;
        _contentStore = contentStore;
        _telemetry = telemetry;
        _timeProvider = timeProvider;
        _delay = delay ?? ((duration, cancellationToken) =>
            Task.Delay(duration, _timeProvider, cancellationToken));
    }

    public async ValueTask<UpdaterRunResult> RunOnceAsync(
        CancellationToken cancellationToken = default)
    {
        var runId = Guid.NewGuid().ToString("N");
        var status = await _contentStore.GetStatusAsync(cancellationToken).ConfigureAwait(false);
        var highestSequence = status.HighestAcceptedSequence;
        await WriteTelemetryAsync(
            runId,
            UpdaterTelemetryEvent.CheckStarted,
            attempt: 0,
            highestSequence,
            candidateSequence: null,
            candidateVersion: null,
            "Checking the configured threat-intelligence channel.",
            cancellationToken).ConfigureAwait(false);

        for (var attempt = 1; attempt <= _configuration.RetryPolicy.MaximumAttempts; attempt++)
        {
            try
            {
                using var download = await _downloader.DownloadAsync(
                    _configuration.ChannelBaseUri,
                    _configuration.DownloadPath,
                    highestSequence,
                    cancellationToken).ConfigureAwait(false);
                var snapshot = await _contentStore.ApplyAsync(
                    download.BundleDirectory,
                    cancellationToken).ConfigureAwait(false);
                var prunedCount = 0;
                try
                {
                    var prune = await _contentStore.PruneAsync(
                        _configuration.MaximumRetainedVersions,
                        cancellationToken).ConfigureAwait(false);
                    prunedCount = prune.DeletedVersionCount;
                }
                catch (ThreatUpdateException exception)
                {
                    await WriteTelemetryAsync(
                        runId,
                        UpdaterTelemetryEvent.RetentionFailed,
                        attempt,
                        snapshot.Manifest.Sequence,
                        snapshot.Manifest.Sequence,
                        snapshot.Manifest.Version,
                        exception.Message,
                        cancellationToken).ConfigureAwait(false);
                }

                await WriteTelemetryAsync(
                    runId,
                    UpdaterTelemetryEvent.UpdateActivated,
                    attempt,
                    snapshot.Manifest.Sequence,
                    snapshot.Manifest.Sequence,
                    snapshot.Manifest.Version,
                    $"Activated signed content using key '{snapshot.Manifest.KeyId}'.",
                    cancellationToken).ConfigureAwait(false);
                return new UpdaterRunResult(
                    UpdaterRunStatus.Activated,
                    attempt,
                    status.ActiveSequence,
                    snapshot.Manifest.Sequence,
                    snapshot.Manifest.Version,
                    prunedCount);
            }
            catch (ThreatUpdateSequenceException exception) when (exception.IsCurrent)
            {
                await WriteTelemetryAsync(
                    runId,
                    UpdaterTelemetryEvent.AlreadyCurrent,
                    attempt,
                    highestSequence,
                    exception.CandidateSequence,
                    status.ActiveVersion,
                    exception.Message,
                    cancellationToken).ConfigureAwait(false);
                return new UpdaterRunResult(
                    UpdaterRunStatus.Current,
                    attempt,
                    status.PreviousSequence,
                    exception.CandidateSequence,
                    status.ActiveVersion,
                    PrunedVersionCount: 0);
            }
            catch (ThreatUpdateDownloadException exception) when (
                exception.IsTransient &&
                attempt < _configuration.RetryPolicy.MaximumAttempts)
            {
                var delay = _configuration.RetryPolicy.GetDelay(attempt);
                await WriteTelemetryAsync(
                    runId,
                    UpdaterTelemetryEvent.RetryScheduled,
                    attempt,
                    highestSequence,
                    candidateSequence: null,
                    candidateVersion: null,
                    $"{exception.Message} Retrying after {delay.TotalSeconds:F0} seconds.",
                    cancellationToken).ConfigureAwait(false);
                await _delay(delay, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is ThreatUpdateDownloadException or
                    ThreatUpdateSequenceException or ThreatUpdateException)
            {
                var telemetryEvent = exception is ThreatUpdateDownloadException
                    ? UpdaterTelemetryEvent.UpdateFailed
                    : UpdaterTelemetryEvent.UpdateRejected;
                await WriteTelemetryAsync(
                    runId,
                    telemetryEvent,
                    attempt,
                    highestSequence,
                    (exception as ThreatUpdateSequenceException)?.CandidateSequence,
                    candidateVersion: null,
                    exception.Message,
                    cancellationToken).ConfigureAwait(false);
                throw;
            }
        }

        throw new InvalidOperationException("The updater retry loop ended unexpectedly.");
    }

    private ValueTask WriteTelemetryAsync(
        string runId,
        UpdaterTelemetryEvent telemetryEvent,
        int attempt,
        long highestSequence,
        long? candidateSequence,
        string? candidateVersion,
        string message,
        CancellationToken cancellationToken) =>
        _telemetry.WriteAsync(
            new UpdaterTelemetryRecord(
                _timeProvider.GetUtcNow(),
                runId,
                _configuration.DeploymentId,
                _configuration.RolloutRing,
                telemetryEvent,
                attempt,
                highestSequence,
                candidateSequence,
                candidateVersion,
                message),
            cancellationToken);
}
