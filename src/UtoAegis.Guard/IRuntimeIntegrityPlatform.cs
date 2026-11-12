using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Guard;

internal interface IRuntimeIntegrityPlatform
{
    ValueTask<IReadOnlyList<RuntimeIntegrityFinding>> AuditAsync(
        RuntimePolicyManifest policy,
        CancellationToken cancellationToken);

    ValueTask RecoverAsync(
        RuntimeIntegrityFinding finding,
        RuntimePolicyManifest policy,
        CancellationToken cancellationToken);
}
