using UtoAegis.Core.PortableExecutable;
using UtoAegis.Core.Reputation;
using UtoAegis.Core.RiskScoring;
using UtoAegis.Core.Scanning;
using UtoAegis.Core.Signatures;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class RiskVerdictAggregatorTests
{
    private static readonly FileHashScanResult SuccessfulHash = FileHashScanResult.Success(
        "sample.bin",
        new string('a', 64),
        100,
        TimeSpan.Zero);

    [TestMethod]
    public void Assess_ExactHashMatch_TakesPrecedenceOverIncompleteAnalysis()
    {
        Assert.IsTrue(MalwareHashIndicator.TryCreate(
            new string('a', 64),
            ThreatClassification.Malware,
            "test",
            null,
            null,
            out var indicator,
            out _));
        var result = new RiskVerdictAggregator().Assess(
            SuccessfulHash,
            HashReputationResult.Malicious(indicator!, DateTimeOffset.UnixEpoch),
            SignatureScanResult.Failure(
                "test",
                SignatureScanStatus.IoError,
                "sample.bin",
                TimeSpan.Zero,
                "failed"),
            null);

        Assert.AreEqual(RiskVerdict.Malicious, result.Verdict);
        Assert.AreEqual(100, result.Confidence);
        Assert.IsTrue(result.HasExactDetection);
    }

    [TestMethod]
    public void Assess_ExactSignature_TakesPrecedenceOverHeuristicScore()
    {
        var signature = SignatureScanResult.Completed(
            "test",
            "sample.bin",
            [new SignatureMatch("rule", "Rule", "test", 0, 4)],
            100,
            TimeSpan.Zero);

        var result = new RiskVerdictAggregator().Assess(
            SuccessfulHash,
            null,
            signature,
            MalformedPe());

        Assert.AreEqual(RiskVerdict.Malicious, result.Verdict);
        Assert.IsTrue(result.Evidence.Any(item =>
            item.Kind == RiskEvidenceKind.ExactByteSignature && item.IsExact));
    }

    [TestMethod]
    public void Assess_ScoreAtReviewThreshold_ReturnsReview()
    {
        var result = new RiskVerdictAggregator(Policy(review: 10, detection: 90)).Assess(
            SuccessfulHash,
            null,
            null,
            MalformedPe());

        Assert.AreEqual(50, result.HeuristicScore.Score);
        Assert.AreEqual(RiskVerdict.Review, result.Verdict);
        Assert.AreEqual(75, result.Confidence);
    }

    [TestMethod]
    public void Assess_ScoreAtDetectionThreshold_ReturnsMaliciousWithoutExactEvidence()
    {
        var result = new RiskVerdictAggregator(Policy(review: 10, detection: 50)).Assess(
            SuccessfulHash,
            null,
            null,
            MalformedPe());

        Assert.AreEqual(RiskVerdict.Malicious, result.Verdict);
        Assert.IsFalse(result.HasExactDetection);
    }

    [TestMethod]
    public void Assess_FailedConfiguredStage_ReturnsInconclusive()
    {
        var result = new RiskVerdictAggregator().Assess(
            SuccessfulHash,
            HashReputationResult.LookupFailed("failed"),
            null,
            null);

        Assert.AreEqual(RiskVerdict.Inconclusive, result.Verdict);
        Assert.AreEqual(50, result.Confidence);
        Assert.IsTrue(result.Evidence.Any(item =>
            item.Kind == RiskEvidenceKind.IncompleteAnalysis));
    }

    [TestMethod]
    public void Assess_CompletedCleanEvidence_ReturnsNoKnownThreat()
    {
        var result = new RiskVerdictAggregator().Assess(
            SuccessfulHash,
            HashReputationResult.Unknown(),
            null,
            null);

        Assert.AreEqual(RiskVerdict.NoKnownThreat, result.Verdict);
        Assert.AreEqual(100, result.Confidence);
        Assert.AreEqual(0, result.HeuristicScore.Score);
    }

    private static RiskScoringPolicy Policy(int review, int detection)
    {
        var caps = Enum.GetValues<RiskFeatureCategory>()
            .ToDictionary(category => category, _ => 100);
        return new RiskScoringPolicy(
            "test",
            1,
            review,
            detection,
            [new RiskScoringRule(
                "pe.analysis.malformed",
                RiskFeatureCategory.Structure,
                50,
                "Malformed test image.")],
            caps);
    }

    private static PortableExecutableAnalysisResult MalformedPe() => new(
        PortableExecutableAnalysisStatus.Malformed,
        100,
        null,
        [],
        PortableExecutableDirectoryFacts.Empty,
        PortableExecutablePlatformFacts.Empty,
        PortableExecutableImageFacts.Empty,
        PortableExecutableIssueCode.InvalidHeaders);
}
