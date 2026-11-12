using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UtoAegis.Core.History;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Response;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;
using UtoAegis.Infrastructure.History;
using UtoAegis.Infrastructure.Monitoring;
using UtoAegis.Infrastructure.Quarantine;
using UtoAegis.Infrastructure.Reputation;
using UtoAegis.Infrastructure.Signatures;
using UtoAegis.Infrastructure.Telemetry;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service;

internal sealed class ServiceWorker(
    ServiceConfiguration configuration,
    ServiceDetectionSources detectionSources,
    ILoggerFactory loggerFactory) : BackgroundService
{
    private readonly ILogger logger = loggerFactory.CreateLogger<ServiceWorker>();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        FileSystemQuarantineStore? quarantineStore = null;
        ServiceThreatContentReloader? contentReloader = null;
        SecurityTelemetrySpool? telemetrySpool = null;
        SecurityTelemetryWriter? securityTelemetry = null;
        var monitorRunId = Guid.NewGuid().ToString("N");
        try
        {
            if (configuration.SecurityTelemetrySpoolPath is not null)
            {
                telemetrySpool = new SecurityTelemetrySpool(
                    configuration.SecurityTelemetrySpoolPath,
                    new SecurityTelemetrySpoolOptions(
                        configuration.TelemetryMaximumRecords));
                await telemetrySpool.InitializeAsync(stoppingToken);
                securityTelemetry = new SecurityTelemetryWriter(
                    telemetrySpool,
                    "monitor",
                    configuration.DeploymentId!);
            }

            var initialScanner = await CreateScannerAsync(
                detectionSources.DatabasePath,
                detectionSources.SignaturePath,
                initializeReputationStore: !detectionSources.IsManagedContent,
                stoppingToken);
            IFileScanner scanner = initialScanner;
            if (detectionSources.IsManagedContent)
            {
                contentReloader = new ServiceThreatContentReloader(
                    detectionSources.ManagedSource!,
                    detectionSources.ManagedContent!,
                    initialScanner,
                    CreateManagedScannerAsync);
                scanner = contentReloader.Scanner;
                ServiceLog.ThreatContentLoaded(
                    logger,
                    detectionSources.ContentVersion!,
                    detectionSources.ContentSequence!.Value,
                    detectionSources.SigningKeyId!,
                    detectionSources.ExpiresUtc!.Value);
                if (detectionSources.ExpiresUtc.Value <= DateTimeOffset.UtcNow)
                {
                    ServiceLog.ThreatContentExpired(
                        logger,
                        detectionSources.ContentVersion!,
                        detectionSources.ExpiresUtc.Value);
                }
            }

            var historyStore = await CreateHistoryStoreAsync(stoppingToken);
            if (configuration.ResponsePolicy.Mode == ResponseMode.Quarantine)
            {
                quarantineStore = new FileSystemQuarantineStore(configuration.VaultPath!);
                await quarantineStore.InitializeAsync(stoppingToken);
            }

            var responseEngine = new DetectionResponseEngine(
                configuration.ResponsePolicy,
                quarantineStore);
            var sink = new ServiceFileMonitorSink(
                loggerFactory.CreateLogger<ServiceFileMonitorSink>(),
                responseEngine,
                historyStore,
                configuration.MonitorRoot,
                configuration.Recursive,
                securityTelemetry);
            var directoryScanner = new DirectoryScanner(
                scanner,
                new DirectoryScanOptions(
                    configuration.Recursive,
                    configuration.MaximumConcurrency,
                    excludedPaths: configuration.OperationalExclusions));
            var monitoringEngine = new FileMonitoringEngine(
                scanner,
                directoryScanner,
                sink,
                new FileMonitorOptions(
                    configuration.DebounceDelay,
                    configuration.RunInitialScan,
                    configuration.OperationalExclusions));

            await using var eventSource = new FileSystemWatcherEventSource(
                configuration.MonitorRoot,
                configuration.Recursive,
                configuration.QueueCapacity,
                configuration.WatcherBufferSize,
                configuration.OperationalExclusions);
            ServiceLog.MonitoringStarted(
                logger,
                configuration.MonitorRoot,
                configuration.ResponsePolicy.Mode);
            await TryWriteTelemetryAsync(
                securityTelemetry,
                "monitor.started",
                monitorRunId,
                new
                {
                    configuration.MonitorRoot,
                    configuration.Recursive,
                    responseMode = configuration.ResponsePolicy.Mode.ToString(),
                    contentVersion = detectionSources.ContentVersion,
                    contentSequence = detectionSources.ContentSequence
                },
                stoppingToken);

            var monitorTask = monitoringEngine
                .RunAsync(configuration.MonitorRoot, eventSource, stoppingToken)
                .AsTask();
            var nextHealthUtc = DateTimeOffset.UtcNow + configuration.HealthInterval;
            var nextReloadUtc = DateTimeOffset.UtcNow + configuration.ContentReloadInterval;
            while (!monitorTask.IsCompleted)
            {
                var nextActionUtc = contentReloader is null || nextHealthUtc <= nextReloadUtc
                    ? nextHealthUtc
                    : nextReloadUtc;
                var delayDuration = nextActionUtc - DateTimeOffset.UtcNow;
                var delay = Task.Delay(
                    delayDuration <= TimeSpan.Zero ? TimeSpan.Zero : delayDuration,
                    stoppingToken);
                if (await Task.WhenAny(monitorTask, delay) == monitorTask)
                {
                    break;
                }

                if (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                var now = DateTimeOffset.UtcNow;
                if (contentReloader is not null && now >= nextReloadUtc)
                {
                    var reload = await contentReloader.CheckAsync(stoppingToken);
                    await WriteReloadResultAsync(
                        reload,
                        contentReloader.Scanner.Generation,
                        securityTelemetry,
                        monitorRunId,
                        stoppingToken);
                    nextReloadUtc = DateTimeOffset.UtcNow + configuration.ContentReloadInterval;
                }

                if (now >= nextHealthUtc)
                {
                    await WriteHealthAsync(
                        sink.Snapshot(),
                        securityTelemetry,
                        monitorRunId,
                        stoppingToken);
                    if (contentReloader is not null)
                    {
                        await WriteThreatContentHealthAsync(
                            contentReloader.Health,
                            securityTelemetry,
                            monitorRunId,
                            stoppingToken);
                    }

                    nextHealthUtc = DateTimeOffset.UtcNow + configuration.HealthInterval;
                }
            }

            var summary = await monitorTask;
            await WriteHealthAsync(
                sink.Snapshot(),
                securityTelemetry,
                monitorRunId,
                stoppingToken);
            if (contentReloader is not null)
            {
                await WriteThreatContentHealthAsync(
                    contentReloader.Health,
                    securityTelemetry,
                    monitorRunId,
                    stoppingToken);
            }
            ServiceLog.MonitoringStopped(
                logger,
                summary.Elapsed.TotalMilliseconds,
                summary.EventCount,
                summary.FileScanCount,
                summary.RecoveryScanCount,
                summary.IssueCount);
            await TryWriteTelemetryAsync(
                securityTelemetry,
                "monitor.stopped",
                monitorRunId,
                new
                {
                    elapsedMilliseconds = summary.Elapsed.TotalMilliseconds,
                    summary.EventCount,
                    summary.FileScanCount,
                    summary.RecoveryScanCount,
                    summary.IssueCount
                },
                stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            ServiceLog.MonitoringStopped(logger, 0, 0, 0, 0, 0);
        }
        finally
        {
            contentReloader?.Dispose();
            quarantineStore?.Dispose();
            if (securityTelemetry is not null)
            {
                securityTelemetry.Dispose();
            }
            else
            {
                telemetrySpool?.Dispose();
            }
        }
    }

    private ValueTask<IFileScanner> CreateManagedScannerAsync(
        ThreatContentSnapshot snapshot,
        CancellationToken cancellationToken) =>
        CreateScannerAsync(
            snapshot.ReputationDatabasePath,
            snapshot.SignatureRulesPath,
            initializeReputationStore: false,
            cancellationToken);

    private async ValueTask<IFileScanner> CreateScannerAsync(
        string? databasePath,
        string? signaturePath,
        bool initializeReputationStore,
        CancellationToken cancellationToken)
    {
        IHashReputationStore? reputationStore = null;
        if (databasePath is not null)
        {
            var store = new SqliteHashReputationStore(databasePath);
            if (initializeReputationStore)
            {
                await store.InitializeAsync(cancellationToken);
            }

            reputationStore = store;
        }

        ISignatureScanner? signatureScanner = null;
        if (signaturePath is not null)
        {
            var ruleFile = await JsonLinesSignatureRuleReader.ReadAsync(
                signaturePath,
                cancellationToken);
            signatureScanner = new FixedByteSignatureScanner(ruleFile.Rules);
            ServiceLog.SignatureRulesLoaded(
                logger,
                ruleFile.Rules.Count,
                ruleFile.DuplicateCount);
        }

        return new CompositeFileScanner(
            new Sha256FileHashScanner(),
            reputationStore,
            signatureScanner);
    }

    private async ValueTask<IScanHistoryStore?> CreateHistoryStoreAsync(
        CancellationToken cancellationToken)
    {
        if (configuration.HistoryPath is null)
        {
            return null;
        }

        var store = new SqliteScanHistoryStore(configuration.HistoryPath);
        await store.InitializeAsync(cancellationToken);
        return store;
    }

    private async ValueTask WriteHealthAsync(
        ServiceHealthSnapshot snapshot,
        SecurityTelemetryWriter? securityTelemetry,
        string correlationId,
        CancellationToken cancellationToken)
    {
        ServiceLog.Health(
            logger,
            snapshot.ScannedFileCount,
            snapshot.DetectionCount,
            snapshot.QuarantinedFileCount,
            snapshot.ResponseFailureCount,
            snapshot.MonitorIssueCount,
            snapshot.HistoryFailureCount);
        await TryWriteTelemetryAsync(
            securityTelemetry,
            "monitor.health",
            correlationId,
            snapshot,
            cancellationToken);
    }

    private async ValueTask WriteReloadResultAsync(
        ThreatContentReloadResult result,
        long generation,
        SecurityTelemetryWriter? securityTelemetry,
        string correlationId,
        CancellationToken cancellationToken)
    {
        if (result.Status == ThreatContentReloadStatus.Reloaded)
        {
            var manifest = result.Snapshot!.Manifest;
            ServiceLog.ThreatContentReloaded(
                logger,
                result.Previous!.Version,
                result.Previous.Sequence,
                manifest.Version,
                manifest.Sequence,
                generation,
                manifest.KeyId,
                manifest.ExpiresUtc);
            if (manifest.ExpiresUtc <= DateTimeOffset.UtcNow)
            {
                ServiceLog.ThreatContentExpired(
                    logger,
                    manifest.Version,
                    manifest.ExpiresUtc);
            }

            await TryWriteTelemetryAsync(
                securityTelemetry,
                "threatContent.reloaded",
                correlationId,
                new
                {
                    previousVersion = result.Previous.Version,
                    previousSequence = result.Previous.Sequence,
                    manifest.Version,
                    manifest.Sequence,
                    generation,
                    manifest.KeyId,
                    manifest.ExpiresUtc
                },
                cancellationToken);
        }
        else if (result.Status == ThreatContentReloadStatus.Rejected && result.ShouldLog)
        {
            ServiceLog.ThreatContentReloadRejected(
                logger,
                result.Active.Version,
                result.Active.Sequence,
                result.Error!);
            await TryWriteTelemetryAsync(
                securityTelemetry,
                "threatContent.reloadRejected",
                correlationId,
                new
                {
                    activeVersion = result.Active.Version,
                    activeSequence = result.Active.Sequence,
                    reason = result.Error
                },
                cancellationToken);
        }
    }

    private async ValueTask WriteThreatContentHealthAsync(
        ServiceThreatContentHealthSnapshot snapshot,
        SecurityTelemetryWriter? securityTelemetry,
        string correlationId,
        CancellationToken cancellationToken)
    {
        ServiceLog.ThreatContentHealth(
            logger,
            snapshot.Version,
            snapshot.Sequence,
            snapshot.ScannerGeneration,
            snapshot.SuccessfulReloadCount,
            snapshot.RejectedReloadCount,
            snapshot.LastCheckedUtc);
        await TryWriteTelemetryAsync(
            securityTelemetry,
            "threatContent.health",
            correlationId,
            snapshot,
            cancellationToken);
    }

    private async ValueTask TryWriteTelemetryAsync<TPayload>(
        SecurityTelemetryWriter? securityTelemetry,
        string eventType,
        string correlationId,
        TPayload payload,
        CancellationToken cancellationToken)
    {
        if (securityTelemetry is null)
        {
            return;
        }

        try
        {
            await securityTelemetry.WriteAsync(
                eventType,
                correlationId,
                payload,
                cancellationToken);
        }
        catch (SecurityTelemetryException exception)
        {
            ServiceLog.SecurityTelemetryFailed(logger, exception);
        }
    }
}
