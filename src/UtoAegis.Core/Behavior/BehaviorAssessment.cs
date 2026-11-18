using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Core.Behavior;

public sealed record BehaviorContribution(
    string FeatureId,
    BehaviorFeatureCategory Category,
    int Strength,
    int Weight,
    int RawPoints,
    int AppliedPoints,
    string Explanation,
    IReadOnlyList<Guid> EventIds);

public sealed record BehaviorCategoryScore(
    BehaviorFeatureCategory Category,
    int RawPoints,
    int Cap,
    int AppliedPoints);

public sealed record BehaviorAssessment(
    string PolicyId,
    int PolicyVersion,
    RiskVerdict Verdict,
    int Score,
    int Confidence,
    BehaviorProviderState ProviderState,
    BehaviorProcessInstance? Subject,
    DateTimeOffset? WindowStartedUtc,
    DateTimeOffset? WindowEndedUtc,
    int EventCount,
    IReadOnlyList<BehaviorRiskFeature> Features,
    IReadOnlyList<BehaviorCategoryScore> Categories,
    IReadOnlyList<BehaviorContribution> Contributions)
{
    public bool IsDetection => Verdict == RiskVerdict.Malicious;
}
