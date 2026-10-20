using UtoAegis.Core.Scanning;
using UtoAegis.Infrastructure.Signatures;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service;

internal sealed class ServiceThreatContentReloader : IDisposable
{
    private readonly IServiceThreatContentSource _source;
    private readonly Func<ThreatContentSnapshot, CancellationToken, ValueTask<IFileScanner>>
        _scannerFactory;
    private ThreatContentIdentity _active;
    private string? _lastFailureFingerprint;

    public ServiceThreatContentReloader(
        IServiceThreatContentSource source,
        IServiceThreatContentLease initialContent,
        IFileScanner initialScanner,
        Func<ThreatContentSnapshot, CancellationToken, ValueTask<IFileScanner>> scannerFactory)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(initialContent);
        ArgumentNullException.ThrowIfNull(initialScanner);
        ArgumentNullException.ThrowIfNull(scannerFactory);
        _source = source;
        _scannerFactory = scannerFactory;
        _active = ThreatContentIdentity.From(initialContent.Snapshot);
        Scanner = new ReloadableFileScanner(
            new ServiceLeasedFileScanner(initialScanner, initialContent));
    }

    public ReloadableFileScanner Scanner { get; }

    public ServiceThreatContentHealthSnapshot Health =>
        new(
            _active.Version,
            _active.Sequence,
            Scanner.Generation,
            SuccessfulReloadCount,
            RejectedReloadCount,
            LastCheckedUtc);

    public long SuccessfulReloadCount { get; private set; }

    public long RejectedReloadCount { get; private set; }

    public DateTimeOffset? LastCheckedUtc { get; private set; }

    public async ValueTask<ThreatContentReloadResult> CheckAsync(
        CancellationToken cancellationToken = default)
    {
        LastCheckedUtc = DateTimeOffset.UtcNow;
        IServiceThreatContentLease? candidateContent = null;
        try
        {
            var status = await _source.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            if (!status.HasActiveContent ||
                status.ActiveVersion is null ||
                status.ActiveSequence is null)
            {
                throw new ThreatUpdateException(
                    "The managed threat-content store no longer has an active version.");
            }

            var candidateIdentity = new ThreatContentIdentity(
                status.ActiveVersion,
                status.ActiveSequence.Value);
            if (candidateIdentity == _active)
            {
                _lastFailureFingerprint = null;
                return ThreatContentReloadResult.Unchanged(_active);
            }

            candidateContent = await _source.GetActiveAsync(cancellationToken)
                .ConfigureAwait(false);
            var snapshot = candidateContent.Snapshot;
            candidateIdentity = ThreatContentIdentity.From(snapshot);
            if (candidateIdentity == _active)
            {
                _lastFailureFingerprint = null;
                return ThreatContentReloadResult.Unchanged(_active);
            }

            var candidateScanner = await _scannerFactory(snapshot, cancellationToken)
                .ConfigureAwait(false);
            Scanner.Replace(new ServiceLeasedFileScanner(
                candidateScanner,
                candidateContent));
            candidateContent = null;
            var previous = _active;
            _active = candidateIdentity;
            SuccessfulReloadCount++;
            _lastFailureFingerprint = null;
            return ThreatContentReloadResult.Reloaded(previous, candidateIdentity, snapshot);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ThreatUpdateException or SignatureRuleFileException)
        {
            RejectedReloadCount++;
            var fingerprint = $"{exception.GetType().FullName}:{exception.Message}";
            var shouldLog = !string.Equals(
                fingerprint,
                _lastFailureFingerprint,
                StringComparison.Ordinal);
            _lastFailureFingerprint = fingerprint;
            return ThreatContentReloadResult.Rejected(_active, exception.Message, shouldLog);
        }
        finally
        {
            candidateContent?.Dispose();
        }
    }

    public void Dispose() => Scanner.Dispose();
}

internal sealed class ServiceLeasedFileScanner(
    IFileScanner scanner,
    IServiceThreatContentLease content) : IFileScanner, IDisposable
{
    public ValueTask<FileScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default) =>
        scanner.ScanAsync(path, cancellationToken);

    public void Dispose() => content.Dispose();
}

internal sealed record ThreatContentIdentity(string Version, long Sequence)
{
    public static ThreatContentIdentity From(ThreatContentSnapshot snapshot) =>
        new(snapshot.Manifest.Version, snapshot.Manifest.Sequence);
}

internal enum ThreatContentReloadStatus
{
    Unchanged,
    Reloaded,
    Rejected
}

internal sealed record ThreatContentReloadResult(
    ThreatContentReloadStatus Status,
    ThreatContentIdentity Active,
    ThreatContentIdentity? Previous,
    ThreatContentSnapshot? Snapshot,
    string? Error,
    bool ShouldLog)
{
    public static ThreatContentReloadResult Unchanged(ThreatContentIdentity active) =>
        new(ThreatContentReloadStatus.Unchanged, active, null, null, null, false);

    public static ThreatContentReloadResult Reloaded(
        ThreatContentIdentity previous,
        ThreatContentIdentity active,
        ThreatContentSnapshot snapshot) =>
        new(ThreatContentReloadStatus.Reloaded, active, previous, snapshot, null, true);

    public static ThreatContentReloadResult Rejected(
        ThreatContentIdentity active,
        string error,
        bool shouldLog) =>
        new(ThreatContentReloadStatus.Rejected, active, null, null, error, shouldLog);
}

internal sealed record ServiceThreatContentHealthSnapshot(
    string Version,
    long Sequence,
    long ScannerGeneration,
    long SuccessfulReloadCount,
    long RejectedReloadCount,
    DateTimeOffset? LastCheckedUtc);
