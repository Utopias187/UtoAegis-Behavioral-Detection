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
        try
        {
            var initialScanner = await CreateScannerAsync(
                detectionSources.DatabasePath,
                detectionSources.SignaturePath,
                initializeReputationStore: !detectionSources.IsManagedContent,
                stoppingToken);
            ServiceThreatContentReloader? contentReloader = null;
            IFileScanner scanner = initialScanner;
            if (detectionSources.IsManagedContent)
            {
                contentReloader = new ServiceThreatContentReloader(
                    detectionSources.ManagedSource!,
                    detectionSources.ManagedSnapshot!,
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
                configuration.Recursive);
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
                    WriteReloadResult(reload, contentReloader.Scanner.Generation);
                    nextReloadUtc = DateTimeOffset.UtcNow + configuration.ContentReloadInterval;
                }

                if (now >= nextHealthUtc)
                {
                    WriteHealth(sink.Snapshot());
                    if (contentReloader is not null)
                    {
                        WriteThreatContentHealth(contentReloader.Health);
                    }

                    nextHealthUtc = DateTimeOffset.UtcNow + configuration.HealthInterval;
                }
            }

            var summary = await monitorTask;
            WriteHealth(sink.Snapshot());
            if (contentReloader is not null)
            {
                WriteThreatContentHealth(contentReloader.Health);
            }
            ServiceLog.MonitoringStopped(
                logger,
                summary.Elapsed.TotalMilliseconds,
                summary.EventCount,
                summary.FileScanCount,
                summary.RecoveryScanCount,
                summary.IssueCount);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            ServiceLog.MonitoringStopped(logger, 0, 0, 0, 0, 0);
        }
        finally
        {
            quarantineStore?.Dispose();
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

    private void WriteHealth(ServiceHealthSnapshot snapshot) =>
        ServiceLog.Health(
            logger,
            snapshot.ScannedFileCount,
            snapshot.DetectionCount,
            snapshot.QuarantinedFileCount,
            snapshot.ResponseFailureCount,
            snapshot.MonitorIssueCount,
            snapshot.HistoryFailureCount);

    private void WriteReloadResult(ThreatContentReloadResult result, long generation)
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
        }
        else if (result.Status == ThreatContentReloadStatus.Rejected && result.ShouldLog)
        {
            ServiceLog.ThreatContentReloadRejected(
                logger,
                result.Active.Version,
                result.Active.Sequence,
                result.Error!);
        }
    }

    private void WriteThreatContentHealth(ServiceThreatContentHealthSnapshot snapshot) =>
        ServiceLog.ThreatContentHealth(
            logger,
            snapshot.Version,
            snapshot.Sequence,
            snapshot.ScannerGeneration,
            snapshot.SuccessfulReloadCount,
            snapshot.RejectedReloadCount,
            snapshot.LastCheckedUtc);
}
