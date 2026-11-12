using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Guard;

internal sealed class RuntimeIntegrityGuardEngine(
    IRuntimeIntegrityPlatform platform,
    IRuntimeRecoveryLimiter recoveryLimiter)
{
    public async ValueTask<RuntimeIntegrityGuardResult> RunAsync(
        RuntimePolicyManifest policy,
        bool recover,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var initial = await platform.AuditAsync(policy, cancellationToken).ConfigureAwait(false);
        if (!recover || initial.Count == 0)
        {
            return new RuntimeIntegrityGuardResult(initial, initial, recover, false, false);
        }

        var recoverable = initial
            .Where(finding => finding.Recoverable)
            .GroupBy(RecoveryTarget, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToArray();
        if (recoverable.Length == 0)
        {
            return new RuntimeIntegrityGuardResult(initial, initial, true, false, false);
        }

        if (!await recoveryLimiter.TryReserveAsync(policy, cancellationToken).ConfigureAwait(false))
        {
            return new RuntimeIntegrityGuardResult(initial, initial, true, false, true);
        }

        var recoveryFailures = new List<RuntimeIntegrityFinding>();
        foreach (var finding in recoverable)
        {
            try
            {
                await platform.RecoverAsync(finding, policy, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception)
            {
                recoveryFailures.Add(new RuntimeIntegrityFinding(
                    RuntimeIntegrityFindingKind.RecoveryFailed,
                    finding.Target,
                    finding.Expected,
                    finding.Actual,
                    false,
                    exception.Message));
            }
        }

        var remaining = await platform.AuditAsync(policy, cancellationToken).ConfigureAwait(false);
        return new RuntimeIntegrityGuardResult(
            initial,
            remaining.Concat(recoveryFailures).ToArray(),
            true,
            true,
            false);
    }

    private static string RecoveryTarget(RuntimeIntegrityFinding finding) =>
        finding.Kind is RuntimeIntegrityFindingKind.ServiceBinaryPathMismatch or
            RuntimeIntegrityFindingKind.ServiceAccountMismatch or
            RuntimeIntegrityFindingKind.ServiceStartModeMismatch
                ? "service:" + finding.Target
                : finding.Kind + ":" + finding.Target;
}
