namespace UtoAegis.Core.RiskScoring;

public sealed record RiskContribution(
    string FeatureId,
    RiskFeatureCategory Category,
    int Strength,
    int Weight,
    int RawPoints,
    int AppliedPoints,
    string Explanation);

public sealed record RiskCategoryScore(
    RiskFeatureCategory Category,
    int RawPoints,
    int Cap,
    int AppliedPoints);

public sealed record RiskScoreResult(
    string PolicyId,
    int PolicyVersion,
    int Score,
    int IgnoredFeatureCount,
    IReadOnlyList<RiskCategoryScore> Categories,
    IReadOnlyList<RiskContribution> Contributions);
