using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class RiskScoringEngineTests
{
    private static readonly IReadOnlyDictionary<RiskFeatureCategory, int> TestCaps =
        Enum.GetValues<RiskFeatureCategory>().ToDictionary(category => category, _ => 10);

    [TestMethod]
    public void DefaultPolicy_HasStableVersionAndCompleteCategoryCaps()
    {
        var policy = RiskScoringPolicy.Default;

        Assert.AreEqual(RiskScoringPolicy.CurrentSchemaVersion, policy.SchemaVersion);
        Assert.AreEqual("utoaegis.pe.default", policy.PolicyId);
        Assert.AreEqual(1, policy.PolicyVersion);
        Assert.HasCount(Enum.GetValues<RiskFeatureCategory>().Length, policy.CategoryCaps);
        Assert.IsLessThan(101, policy.DetectionThreshold);
        Assert.IsLessThan(policy.DetectionThreshold, policy.ReviewThreshold);
    }

    [TestMethod]
    public void Constructor_DuplicateRuleId_Throws()
    {
        var rule = Rule("pe.test", RiskFeatureCategory.Structure, 10);

        Assert.ThrowsExactly<ArgumentException>(() =>
            new RiskScoringPolicy("test", 1, 20, 80, [rule, rule], TestCaps));
    }

    [TestMethod]
    public void Constructor_UnorderedThresholds_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new RiskScoringPolicy(
                "test",
                1,
                80,
                80,
                [Rule("pe.test", RiskFeatureCategory.Structure, 10)],
                TestCaps));
    }

    [TestMethod]
    public void Score_AppliesStrengthWeightAndCategoryCap()
    {
        var policy = new RiskScoringPolicy(
            "test",
            1,
            20,
            80,
            [
                Rule("pe.a", RiskFeatureCategory.Structure, 10),
                Rule("pe.b", RiskFeatureCategory.Structure, 10),
                Rule("pe.c", RiskFeatureCategory.Network, 8)
            ],
            TestCaps);
        var engine = new RiskScoringEngine(policy);

        var result = engine.Score(
        [
            new RiskFeature("pe.a", RiskFeatureCategory.Structure, 100),
            new RiskFeature("pe.b", RiskFeatureCategory.Structure, 50),
            new RiskFeature("pe.c", RiskFeatureCategory.Network, 50)
        ]);

        Assert.AreEqual(14, result.Score);
        var structure = result.Categories.Single(category =>
            category.Category == RiskFeatureCategory.Structure);
        Assert.AreEqual(15, structure.RawPoints);
        Assert.AreEqual(10, structure.AppliedPoints);
        Assert.AreEqual(4, result.Contributions.Single(contribution =>
            contribution.FeatureId == "pe.c").AppliedPoints);
    }

    [TestMethod]
    public void Score_InputOrder_DoesNotChangeResult()
    {
        var features = new[]
        {
            new RiskFeature("pe.section.write-execute", RiskFeatureCategory.Memory, 100),
            new RiskFeature("pe.overlay.present", RiskFeatureCategory.Packing, 75),
            new RiskFeature("pe.imports.network", RiskFeatureCategory.Network, 50)
        };
        var engine = new RiskScoringEngine();

        var forward = engine.Score(features);
        var reverse = engine.Score(features.Reverse().ToArray());

        Assert.AreEqual(forward.Score, reverse.Score);
        Assert.AreEqual(forward.IgnoredFeatureCount, reverse.IgnoredFeatureCount);
        CollectionAssert.AreEqual(forward.Categories.ToArray(), reverse.Categories.ToArray());
        CollectionAssert.AreEqual(
            forward.Contributions.ToArray(),
            reverse.Contributions.ToArray());
    }

    [TestMethod]
    public void Score_UnknownFeature_IsCountedAndIgnored()
    {
        var result = new RiskScoringEngine().Score(
        [
            new RiskFeature("pe.unknown", RiskFeatureCategory.Structure, 100)
        ]);

        Assert.AreEqual(0, result.Score);
        Assert.AreEqual(1, result.IgnoredFeatureCount);
        Assert.IsEmpty(result.Contributions);
    }

    private static RiskScoringRule Rule(
        string id,
        RiskFeatureCategory category,
        int weight) =>
        new(id, category, weight, "Trusted test explanation.");
}
