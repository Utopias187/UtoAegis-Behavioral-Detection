using System.Text.Json;
using UtoAegis.Core.PortableExecutable;
using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class RiskCalibrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [TestMethod]
    public void CalibrationCorpus_MatchesLockedScoresAndVerdicts()
    {
        var policy = RiskScoringPolicy.Default;
        var engine = new RiskScoringEngine(policy);

        foreach (var item in ReadCorpus())
        {
            var result = engine.Score(ToFeatures(item));
            var verdict = Verdict(result.Score, policy);

            Assert.AreEqual(item.ExpectedScore, result.Score, item.Id);
            Assert.AreEqual(item.ExpectedVerdict, verdict.ToString(), item.Id);
            Assert.AreEqual("utoaegis.pe.default", result.PolicyId, item.Id);
            Assert.AreEqual(1, result.PolicyVersion, item.Id);
        }
    }

    [TestMethod]
    public void Score_PermutedFeatures_ProducesByteIdenticalJson()
    {
        var item = ReadCorpus().Single(value => value.Id == "multi-category-high-risk");
        var features = ToFeatures(item);
        var engine = new RiskScoringEngine();

        var forward = JsonSerializer.Serialize(engine.Score(features), JsonOptions);
        var reverse = JsonSerializer.Serialize(engine.Score(features.Reverse().ToArray()), JsonOptions);

        Assert.AreEqual(forward, reverse);
    }

    [TestMethod]
    public async Task RealManagedTestAssembly_RemainsBelowReviewThreshold()
    {
        var analysis = await new PortableExecutableAnalyzer().AnalyzeAsync(
            typeof(RiskCalibrationTests).Assembly.Location);
        var score = new RiskScoringEngine().Score(
            PortableExecutableRiskFeatureExtractor.Extract(analysis));

        Assert.AreEqual(PortableExecutableAnalysisStatus.Analyzed, analysis.Status);
        Assert.IsLessThan(RiskScoringPolicy.Default.ReviewThreshold, score.Score);
    }

    [TestMethod]
    public void IsolatedCommonSignals_RemainBelowReviewThreshold()
    {
        var engine = new RiskScoringEngine();
        var signals = new[]
        {
            new RiskFeature("pe.hardening.no-aslr", RiskFeatureCategory.Hardening, 100),
            new RiskFeature("pe.hardening.no-nx", RiskFeatureCategory.Hardening, 100),
            new RiskFeature("pe.imports.network", RiskFeatureCategory.Network, 25),
            new RiskFeature("pe.overlay.present", RiskFeatureCategory.Packing, 25)
        };

        foreach (var signal in signals)
        {
            Assert.IsLessThan(
                RiskScoringPolicy.Default.ReviewThreshold,
                engine.Score([signal]).Score,
                signal.Id);
        }
    }

    [TestMethod]
    public void CorrelatedMemorySignals_AreLimitedByCategoryCap()
    {
        var item = ReadCorpus().Single(value => value.Id == "correlated-memory-signals-capped");
        var result = new RiskScoringEngine().Score(ToFeatures(item));
        var memory = result.Categories.Single(value => value.Category == RiskFeatureCategory.Memory);

        Assert.IsGreaterThan(memory.Cap, memory.RawPoints);
        Assert.AreEqual(memory.Cap, memory.AppliedPoints);
        Assert.AreEqual(30, result.Score);
    }

    private static CalibrationCase[] ReadCorpus()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "RiskScoring",
            "calibration-corpus.json");
        return JsonSerializer.Deserialize<CalibrationCase[]>(File.ReadAllText(path), JsonOptions) ??
            throw new InvalidOperationException("The risk calibration corpus is invalid.");
    }

    private static RiskFeature[] ToFeatures(CalibrationCase item) =>
        item.Features.Select(feature => new RiskFeature(
            feature.Id,
            Enum.Parse<RiskFeatureCategory>(feature.Category, ignoreCase: false),
            feature.Strength)).ToArray();

    private static RiskVerdict Verdict(int score, RiskScoringPolicy policy) =>
        score >= policy.DetectionThreshold
            ? RiskVerdict.Malicious
            : score >= policy.ReviewThreshold
                ? RiskVerdict.Review
                : RiskVerdict.NoKnownThreat;

    private sealed record CalibrationCase(
        string Id,
        int ExpectedScore,
        string ExpectedVerdict,
        IReadOnlyList<CalibrationFeature> Features);

    private sealed record CalibrationFeature(string Id, string Category, int Strength);
}
