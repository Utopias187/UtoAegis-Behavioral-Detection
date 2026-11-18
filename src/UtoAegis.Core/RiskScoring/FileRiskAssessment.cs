namespace UtoAegis.Core.RiskScoring;

public sealed record FileRiskAssessment(
    RiskVerdict Verdict,
    int Confidence,
    RiskScoreResult HeuristicScore,
    IReadOnlyList<RiskEvidence> Evidence)
{
    public bool IsDetection => Verdict == RiskVerdict.Malicious;

    public bool HasExactDetection => Evidence.Any(item => item.IsExact);
}
