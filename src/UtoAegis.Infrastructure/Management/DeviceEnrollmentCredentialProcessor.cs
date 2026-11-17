using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceEnrollmentCredentialProcessor
{
    private readonly SignedDeviceEnrollmentCredentialVerifier verifier;
    private readonly DeviceEnrollmentStateStore stateStore;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan clockSkew;

    public DeviceEnrollmentCredentialProcessor(
        SignedDeviceEnrollmentCredentialVerifier verifier,
        DeviceEnrollmentStateStore stateStore,
        TimeProvider? timeProvider = null,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(stateStore);
        this.clockSkew = clockSkew ?? TimeSpan.FromMinutes(5);
        if (this.clockSkew < TimeSpan.Zero || this.clockSkew > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkew));
        }

        this.verifier = verifier;
        this.stateStore = stateStore;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<DeviceEnrollmentStateSnapshot> ApplyAsync(
        ReadOnlyMemory<byte> credentialBytes,
        string signatureBase64,
        DeviceIdentityState identity,
        CancellationToken cancellationToken = default)
    {
        var verified = verifier.Verify(credentialBytes, signatureBase64, identity);
        var snapshot = await stateStore.AcceptAsync(verified, cancellationToken)
            .ConfigureAwait(false);
        EnsureActive(snapshot);
        return snapshot;
    }

    public async ValueTask<DeviceEnrollmentStateSnapshot> RequireActiveAsync(
        CancellationToken cancellationToken = default)
    {
        var snapshot = await stateStore.LoadAsync(cancellationToken).ConfigureAwait(false) ??
            throw new DeviceManagementException(
                "No durable device enrollment is available.");
        EnsureActive(snapshot);
        return snapshot;
    }

    private void EnsureActive(DeviceEnrollmentStateSnapshot snapshot)
    {
        if (snapshot.Status != DeviceEnrollmentStatus.Active)
        {
            throw new DeviceManagementException(
                $"The durable device enrollment is {snapshot.Status.ToString().ToLowerInvariant()}.");
        }

        if (snapshot.ExpiresUtc <= timeProvider.GetUtcNow() - clockSkew)
        {
            throw new DeviceManagementException(
                "The durable device enrollment has expired.");
        }
    }
}
