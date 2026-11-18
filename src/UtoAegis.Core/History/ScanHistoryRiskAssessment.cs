using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Core.History;

public sealed record ScanHistoryRiskAssessment(
    RiskVerdict Verdict,
    int Confidence,
    string PolicyId,
    int PolicyVersion,
    int Score,
    bool HasExactDetection,
    IReadOnlyList<string> TopFeatureIds)
{
    public static ScanHistoryRiskAssessment FromResult(FileRiskAssessment result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return new ScanHistoryRiskAssessment(
            result.Verdict,
            result.Confidence,
            result.HeuristicScore.PolicyId,
            result.HeuristicScore.PolicyVersion,
            result.HeuristicScore.Score,
            result.HasExactDetection,
            result.HeuristicScore.Contributions
                .Where(item => item.AppliedPoints > 0)
                .OrderByDescending(item => item.AppliedPoints)
                .ThenBy(item => item.FeatureId, StringComparer.Ordinal)
                .Take(5)
                .Select(item => item.FeatureId)
                .ToArray());
    }
}
