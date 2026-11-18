using Microsoft.Extensions.Logging;
using UtoAegis.Core.Monitoring;
using UtoAegis.Core.Response;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Behavior;
using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Service;

internal static partial class ServiceLog
{
    [LoggerMessage(
        EventId = 100,
        Level = LogLevel.Information,
        Message = "UtoAegis monitoring started for {MonitorRoot} in {ResponseMode} mode.")]
    public static partial void MonitoringStarted(
        ILogger logger,
        string monitorRoot,
        ResponseMode responseMode);

    [LoggerMessage(
        EventId = 101,
        Level = LogLevel.Information,
        Message = "Loaded {RuleCount} signature rules; ignored {DuplicateCount} duplicates.")]
    public static partial void SignatureRulesLoaded(
        ILogger logger,
        int ruleCount,
        int duplicateCount);

    [LoggerMessage(
        EventId = 102,
        Level = LogLevel.Information,
        Message = "Health: scanned={Scanned}, detections={Detections}, quarantined={Quarantined}, responseFailures={ResponseFailures}, monitorIssues={MonitorIssues}, historyFailures={HistoryFailures}.")]
    public static partial void Health(
        ILogger logger,
        long scanned,
        long detections,
        long quarantined,
        long responseFailures,
        long monitorIssues,
        long historyFailures);

    [LoggerMessage(
        EventId = 103,
        Level = LogLevel.Information,
        Message = "Monitoring stopped after {ElapsedMilliseconds} ms: events={Events}, fileScans={FileScans}, recoveryScans={RecoveryScans}, issues={Issues}.")]
    public static partial void MonitoringStopped(
        ILogger logger,
        double elapsedMilliseconds,
        long events,
        long fileScans,
        long recoveryScans,
        long issues);

    [LoggerMessage(
        EventId = 104,
        Level = LogLevel.Information,
        Message = "Loaded authenticated threat content {Version} at sequence {Sequence} using key {KeyId}; expires {ExpiresUtc}.")]
    public static partial void ThreatContentLoaded(
        ILogger logger,
        string version,
        long sequence,
        string keyId,
        DateTimeOffset expiresUtc);

    [LoggerMessage(
        EventId = 105,
        Level = LogLevel.Information,
        Message = "Reloaded authenticated threat content from {PreviousVersion} sequence {PreviousSequence} to {Version} sequence {Sequence} as scanner generation {Generation} using key {KeyId}; expires {ExpiresUtc}.")]
    public static partial void ThreatContentReloaded(
        ILogger logger,
        string previousVersion,
        long previousSequence,
        string version,
        long sequence,
        long generation,
        string keyId,
        DateTimeOffset expiresUtc);

    [LoggerMessage(
        EventId = 106,
        Level = LogLevel.Information,
        Message = "Threat-content health: version={Version}, sequence={Sequence}, scannerGeneration={ScannerGeneration}, reloads={SuccessfulReloads}, rejected={RejectedReloads}, lastChecked={LastCheckedUtc}.")]
    public static partial void ThreatContentHealth(
        ILogger logger,
        string version,
        long sequence,
        long scannerGeneration,
        long successfulReloads,
        long rejectedReloads,
        DateTimeOffset? lastCheckedUtc);

    [LoggerMessage(
        EventId = 107,
        Level = LogLevel.Information,
        Message = "Loaded authenticated runtime policy {PolicyId} sequence {Sequence} using key {KeyId}; expires {ExpiresUtc}; manifest SHA-256 {ManifestSha256}.")]
    public static partial void RuntimePolicyLoaded(
        ILogger logger,
        string policyId,
        long sequence,
        string keyId,
        DateTimeOffset expiresUtc,
        string manifestSha256);

    [LoggerMessage(
        EventId = 108,
        Level = LogLevel.Information,
        Message = "Behavior monitoring started for generation {CollectorGenerationId}; poll interval={PollIntervalMilliseconds} ms.")]
    public static partial void BehaviorMonitoringStarted(
        ILogger logger,
        Guid collectorGenerationId,
        double pollIntervalMilliseconds);

    [LoggerMessage(
        EventId = 200,
        Level = LogLevel.Debug,
        Message = "Scanned {Path}; completed={Completed}, detected={Detected}.")]
    public static partial void FileScanned(
        ILogger logger,
        string path,
        bool completed,
        bool detected);

    [LoggerMessage(
        EventId = 201,
        Level = LogLevel.Information,
        Message = "Recovery scan {Reason} completed: status={Status}, files={Files}, detections={Detections}, issues={Issues}.")]
    public static partial void RecoveryScanCompleted(
        ILogger logger,
        MonitorRecoveryReason reason,
        DirectoryScanStatus status,
        int files,
        int detections,
        int issues);

    [LoggerMessage(
        EventId = 202,
        Level = LogLevel.Warning,
        Message = "Behavior assessment for PID {ProcessId}: verdict={Verdict}, score={Score}, confidence={Confidence}, response={ResponseDisposition}.")]
    public static partial void BehaviorAssessment(
        ILogger logger,
        int processId,
        RiskVerdict verdict,
        int score,
        int confidence,
        string responseDisposition);

    [LoggerMessage(
        EventId = 300,
        Level = LogLevel.Warning,
        Message = "Detection response for {Path}: {Decision}. {Reason}")]
    public static partial void DetectionResponse(
        ILogger logger,
        string path,
        ResponseDecisionKind decision,
        string reason);

    [LoggerMessage(
        EventId = 301,
        Level = LogLevel.Warning,
        Message = "Monitor issue {Kind} for {Path}: {Message}")]
    public static partial void MonitorIssue(
        ILogger logger,
        FileMonitorIssueKind kind,
        string? path,
        string message);

    [LoggerMessage(
        EventId = 302,
        Level = LogLevel.Warning,
        Message = "Active authenticated threat content {Version} expired at {ExpiresUtc}; continuing with the last known-good version.")]
    public static partial void ThreatContentExpired(
        ILogger logger,
        string version,
        DateTimeOffset expiresUtc);

    [LoggerMessage(
        EventId = 303,
        Level = LogLevel.Warning,
        Message = "Rejected a threat-content reload and retained {ActiveVersion} sequence {ActiveSequence}: {Reason}")]
    public static partial void ThreatContentReloadRejected(
        ILogger logger,
        string activeVersion,
        long activeSequence,
        string reason);

    [LoggerMessage(
        EventId = 400,
        Level = LogLevel.Error,
        Message = "Scan history persistence failed.")]
    public static partial void HistoryFailed(ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 401,
        Level = LogLevel.Error,
        Message = "Security telemetry persistence failed; monitoring continues locally.")]
    public static partial void SecurityTelemetryFailed(ILogger logger, Exception exception);
}
