namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed record ThreatContentPruneResult(
    int DeletedVersionCount,
    int RetainedVersionCount,
    IReadOnlyList<string> DeletedVersions,
    IReadOnlyList<string> PinnedVersions);
