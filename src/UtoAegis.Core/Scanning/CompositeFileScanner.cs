using UtoAegis.Core.PortableExecutable;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.RiskScoring;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.Scanning;

public sealed class CompositeFileScanner : IFileScanner
{
    private readonly IFileHashScanner _hashScanner;
    private readonly IHashReputationStore? _reputationStore;
    private readonly ISignatureScanner? _signatureScanner;
    private readonly PortableExecutableAnalyzer? _portableExecutableAnalyzer;
    private readonly RiskVerdictAggregator _riskAggregator;

    public CompositeFileScanner(
        IFileHashScanner hashScanner,
        IHashReputationStore? reputationStore = null,
        ISignatureScanner? signatureScanner = null,
        PortableExecutableAnalyzer? portableExecutableAnalyzer = null,
        RiskVerdictAggregator? riskAggregator = null)
    {
        ArgumentNullException.ThrowIfNull(hashScanner);
        _hashScanner = hashScanner;
        _reputationStore = reputationStore;
        _signatureScanner = signatureScanner;
        _portableExecutableAnalyzer = portableExecutableAnalyzer;
        _riskAggregator = riskAggregator ?? new RiskVerdictAggregator();
    }

    public async ValueTask<FileScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        FileMetadata? initialMetadata = null;
        if ((_signatureScanner is not null || _portableExecutableAnalyzer is not null) &&
            FileMetadata.TryCapture(path, out var metadata))
        {
            initialMetadata = metadata;
        }

        var hash = await _hashScanner
            .ScanAsync(path, cancellationToken)
            .ConfigureAwait(false);
        if (!hash.IsSuccess)
        {
            var failedRisk = _riskAggregator.Assess(hash, null, null, null);
            return new FileScanResult(
                hash,
                Reputation: null,
                Signatures: null,
                Risk: failedRisk);
        }

        HashReputationResult? reputation = null;
        if (_reputationStore is not null)
        {
            reputation = await _reputationStore
                .LookupAsync(hash.Sha256!, cancellationToken)
                .ConfigureAwait(false);
        }

        PortableExecutableAnalysisResult? portableExecutable = null;
        if (_portableExecutableAnalyzer is not null)
        {
            portableExecutable = await _portableExecutableAnalyzer
                .AnalyzeAsync(path, cancellationToken)
                .ConfigureAwait(false);
        }

        SignatureScanResult? signatures = null;
        if (_signatureScanner is not null)
        {
            signatures = await _signatureScanner
                .ScanAsync(path, cancellationToken)
                .ConfigureAwait(false);
        }

        if (initialMetadata is { } captured && !captured.Matches(path))
        {
            if (signatures?.IsCompleted == true)
            {
                signatures = SignatureScanResult.Failure(
                    _signatureScanner!.EngineName,
                    SignatureScanStatus.FileChangedDuringScan,
                    hash.Path,
                    signatures.Elapsed,
                    "The file changed between detection stages; combined results were discarded.");
            }

            if (portableExecutable is not null)
            {
                portableExecutable = new PortableExecutableAnalysisResult(
                    PortableExecutableAnalysisStatus.UnsafeInput,
                    portableExecutable.FileSizeBytes,
                    null,
                    [],
                    PortableExecutableDirectoryFacts.Empty,
                    PortableExecutablePlatformFacts.Empty,
                    PortableExecutableImageFacts.Empty,
                    PortableExecutableIssueCode.FileChanged);
            }
        }

        var risk = _riskAggregator.Assess(hash, reputation, signatures, portableExecutable);
        return new FileScanResult(hash, reputation, signatures, portableExecutable, risk);
    }

    private readonly record struct FileMetadata(long Length, DateTime LastWriteTimeUtc)
    {
        public static bool TryCapture(string path, out FileMetadata metadata)
        {
            try
            {
                var file = new FileInfo(Path.GetFullPath(path));
                file.Refresh();
                if (!file.Exists)
                {
                    metadata = default;
                    return false;
                }

                metadata = new FileMetadata(file.Length, file.LastWriteTimeUtc);
                return true;
            }
            catch (Exception exception) when (
                exception is ArgumentException or
                NotSupportedException or
                IOException or
                UnauthorizedAccessException)
            {
                metadata = default;
                return false;
            }
        }

        public bool Matches(string path) =>
            TryCapture(path, out var current) && current == this;
    }
}
