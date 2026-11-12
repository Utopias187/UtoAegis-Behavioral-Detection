namespace UtoAegis.Guard;

internal sealed record RuntimeIntegrityGuardResult(
    IReadOnlyList<RuntimeIntegrityFinding> InitialFindings,
    IReadOnlyList<RuntimeIntegrityFinding> RemainingFindings,
    bool RecoveryRequested,
    bool RecoveryAttempted,
    bool RecoveryRateLimited)
{
    public bool IsHealthy => RemainingFindings.Count == 0;
}
