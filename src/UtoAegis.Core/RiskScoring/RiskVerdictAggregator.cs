using UtoAegis.Core.PortableExecutable;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.RiskScoring;

public sealed class RiskVerdictAggregator
{
    private readonly RiskScoringPolicy policy;
    private readonly RiskScoringEngine engine;

    public RiskVerdictAggregator(RiskScoringPolicy? policy = null)
    {
        this.policy = policy ?? RiskScoringPolicy.Default;
        engine = new RiskScoringEngine(this.policy);
    }

    public FileRiskAssessment Assess(
        FileHashScanResult fileHash,
        HashReputationResult? reputation,
        SignatureScanResult? signatures,
        PortableExecutableAnalysisResult? portableExecutable)
    {
        ArgumentNullException.ThrowIfNull(fileHash);

        var features = portableExecutable is null
            ? Array.Empty<RiskFeature>()
            : PortableExecutableRiskFeatureExtractor.Extract(portableExecutable).ToArray();
        var score = engine.Score(features);
        var evidence = score.Contributions
            .Where(contribution => contribution.AppliedPoints > 0)
            .Select(contribution => new RiskEvidence(
                RiskEvidenceKind.PortableExecutableHeuristic,
                contribution.FeatureId,
                contribution.Explanation,
                IsExact: false))
            .ToList();

        if (reputation?.Status == HashReputationStatus.Malicious)
        {
            evidence.Insert(0, new RiskEvidence(
                RiskEvidenceKind.ExactHashReputation,
                "hash-reputation",
                "The SHA-256 matched a configured malicious reputation record.",
                IsExact: true));
        }

        if (signatures?.Status == SignatureScanStatus.Detected)
        {
            evidence.Insert(0, new RiskEvidence(
                RiskEvidenceKind.ExactByteSignature,
                "byte-signature",
                "A configured byte signature matched the file.",
                IsExact: true));
        }

        if (evidence.Any(item => item.IsExact))
        {
            return new FileRiskAssessment(RiskVerdict.Malicious, 100, score, evidence);
        }

        var incomplete = GetIncompleteSources(fileHash, reputation, signatures, portableExecutable);
        if (incomplete.Count > 0)
        {
            evidence.AddRange(incomplete.Select(source => new RiskEvidence(
                RiskEvidenceKind.IncompleteAnalysis,
                source,
                "A configured analysis stage did not complete.",
                IsExact: false)));
            return new FileRiskAssessment(RiskVerdict.Inconclusive, 50, score, evidence);
        }

        var confidence = portableExecutable?.Status is
            PortableExecutableAnalysisStatus.Malformed or
            PortableExecutableAnalysisStatus.Unsupported
            ? 75
            : 100;
        var verdict = score.Score >= policy.DetectionThreshold
            ? RiskVerdict.Malicious
            : score.Score >= policy.ReviewThreshold
                ? RiskVerdict.Review
                : RiskVerdict.NoKnownThreat;
        return new FileRiskAssessment(verdict, confidence, score, evidence);
    }

    private static List<string> GetIncompleteSources(
        FileHashScanResult fileHash,
        HashReputationResult? reputation,
        SignatureScanResult? signatures,
        PortableExecutableAnalysisResult? portableExecutable)
    {
        var sources = new List<string>(4);
        if (!fileHash.IsSuccess)
        {
            sources.Add("file-hash");
        }

        if (reputation?.Status == HashReputationStatus.LookupFailed)
        {
            sources.Add("hash-reputation");
        }

        if (signatures is not null && !signatures.IsCompleted)
        {
            sources.Add("byte-signature");
        }

        if (portableExecutable?.Status is
            PortableExecutableAnalysisStatus.UnsafeInput or
            PortableExecutableAnalysisStatus.IoError)
        {
            sources.Add("portable-executable");
        }

        return sources;
    }
}
