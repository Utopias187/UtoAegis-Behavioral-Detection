using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Guard;

internal interface IRuntimeRecoveryLimiter
{
    ValueTask<bool> TryReserveAsync(
        RuntimePolicyManifest policy,
        CancellationToken cancellationToken);
}
