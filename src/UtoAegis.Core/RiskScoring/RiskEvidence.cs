namespace UtoAegis.Core.RiskScoring;

public enum RiskEvidenceKind
{
    ExactHashReputation = 0,
    ExactByteSignature = 1,
    PortableExecutableHeuristic = 2,
    IncompleteAnalysis = 3
}

public sealed record RiskEvidence(
    RiskEvidenceKind Kind,
    string Source,
    string Summary,
    bool IsExact);
