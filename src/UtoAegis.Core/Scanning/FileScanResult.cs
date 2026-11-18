using UtoAegis.Core.PortableExecutable;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.RiskScoring;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.Scanning;

public sealed record FileScanResult(
    FileHashScanResult FileHash,
    HashReputationResult? Reputation,
    SignatureScanResult? Signatures,
    PortableExecutableAnalysisResult? PortableExecutable = null,
    FileRiskAssessment? Risk = null)
{
    public string? Path => FileHash.Path ?? Signatures?.Path;

    public bool IsDetected => Risk?.IsDetection ??
        (Reputation?.Status == HashReputationStatus.Malicious ||
        Signatures?.Status == SignatureScanStatus.Detected);

    public bool IsCompleted => (Risk is null || Risk.Verdict != RiskVerdict.Inconclusive) &&
        FileHash.IsSuccess &&
        Reputation?.Status != HashReputationStatus.LookupFailed &&
        (Signatures is null || Signatures.IsCompleted) &&
        PortableExecutable?.Status is not (
            PortableExecutableAnalysisStatus.UnsafeInput or
            PortableExecutableAnalysisStatus.IoError);
}
