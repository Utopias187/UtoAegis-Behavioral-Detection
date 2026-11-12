using Microsoft.Extensions.Logging;
using UtoAegis.Core.History;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Response;
using UtoAegis.Core.Scanning;
using UtoAegis.Infrastructure.Telemetry;

namespace UtoAegis.Service;

internal sealed class ServiceFileMonitorSink(
    ILogger logger,
    DetectionResponseEngine responseEngine,
    IScanHistoryStore? historyStore,
    string monitorRoot,
    bool recursive,
    SecurityTelemetryWriter? securityTelemetry = null) : IFileMonitorSink
{
    private long scannedFileCount;
    private long detectionCount;
    private long quarantinedFileCount;
    private long responseFailureCount;
    private long monitorIssueCount;
    private long historyFailureCount;

    public async ValueTask FileScannedAsync(
        FileMonitorScanResult result,
        CancellationToken cancellationToken = default)
    {
        var correlationId = Guid.NewGuid();
        Interlocked.Increment(ref scannedFileCount);
        ServiceLog.FileScanned(
            logger,
            result.Path,
            result.Result.IsCompleted,
            result.Result.IsDetected);
        await PersistAsync(
            ScanHistoryRecord.FromFileScan(
                correlationId,
                result.Path,
                result.StartedUtc,
                result.CompletedUtc,
                result.Result),
            cancellationToken);
        await RespondAsync(result.Result, correlationId, cancellationToken);
    }

    public async ValueTask RecoveryScanCompletedAsync(
        FileMonitorRecoveryResult result,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Add(ref scannedFileCount, result.Result.Files.Count);
        ServiceLog.RecoveryScanCompleted(
            logger,
            result.Reason,
            result.Result.Status,
            result.Result.Files.Count,
            result.Result.DetectedFileCount,
            result.Result.Issues.Count);
        await PersistAsync(
            ScanHistoryRecord.FromDirectoryScan(
                Guid.NewGuid(),
                result.Result.RootPath ?? monitorRoot,
                recursive,
                result.StartedUtc,
                result.CompletedUtc,
                result.Result),
            cancellationToken);

        foreach (var file in result.Result.Files.Where(file => file.Result.IsDetected))
        {
            await RespondAsync(file.Result, Guid.NewGuid(), cancellationToken);
        }
    }

    public ValueTask IssueAsync(
        FileMonitorIssue issue,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref monitorIssueCount);
        ServiceLog.MonitorIssue(
            logger,
            issue.Kind,
            issue.Path,
            issue.Message);
        return ValueTask.CompletedTask;
    }

    public ServiceHealthSnapshot Snapshot() =>
        new(
            Interlocked.Read(ref scannedFileCount),
            Interlocked.Read(ref detectionCount),
            Interlocked.Read(ref quarantinedFileCount),
            Interlocked.Read(ref responseFailureCount),
            Interlocked.Read(ref monitorIssueCount),
            Interlocked.Read(ref historyFailureCount));

    private async ValueTask RespondAsync(
        FileScanResult result,
        Guid correlationId,
        CancellationToken cancellationToken)
    {
        if (!result.IsDetected)
        {
            return;
        }

        Interlocked.Increment(ref detectionCount);
        var decision = await responseEngine.RespondAsync(result, cancellationToken);
        if (decision.Kind == ResponseDecisionKind.Quarantined)
        {
            Interlocked.Increment(ref quarantinedFileCount);
        }
        else if (decision.Kind == ResponseDecisionKind.QuarantineFailed)
        {
            Interlocked.Increment(ref responseFailureCount);
        }

        ServiceLog.DetectionResponse(
            logger,
            decision.Path ?? "unknown",
            decision.Kind,
            decision.Reason);
        if (securityTelemetry is not null)
        {
            try
            {
                await securityTelemetry.WriteAsync(
                    "detection.response",
                    correlationId.ToString("N"),
                    new
                    {
                        path = decision.Path,
                        sha256 = result.FileHash.Sha256,
                        fileSizeBytes = result.FileHash.FileSizeBytes,
                        reputation = result.Reputation?.Status.ToString(),
                        signatureIds = result.Signatures?.Matches
                            .Select(match => match.RuleId)
                            .ToArray() ?? [],
                        decision = decision.Kind.ToString(),
                        decision.Reason
                    },
                    cancellationToken);
            }
            catch (SecurityTelemetryException exception)
            {
                ServiceLog.SecurityTelemetryFailed(logger, exception);
            }
        }
    }

    private async ValueTask PersistAsync(
        ScanHistoryRecord record,
        CancellationToken cancellationToken)
    {
        if (historyStore is null)
        {
            return;
        }

        try
        {
            await historyStore.AppendAsync(record, cancellationToken);
        }
        catch (ScanHistoryStoreException exception)
        {
            Interlocked.Increment(ref historyFailureCount);
            ServiceLog.HistoryFailed(logger, exception);
        }
    }
}
