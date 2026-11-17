using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceEnrollmentCoordinator
{
    private readonly DeviceEnrollmentProofVerifier proofVerifier;
    private readonly SqliteDeviceRequestReplayStore replayStore;
    private readonly SqliteEnrollmentBootstrapStore enrollmentStore;
    private readonly DeviceEnrollmentCredentialIssuer credentialIssuer;
    private readonly Uri managementOrigin;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan credentialLifetime;

    public DeviceEnrollmentCoordinator(
        DeviceEnrollmentProofVerifier proofVerifier,
        SqliteDeviceRequestReplayStore replayStore,
        SqliteEnrollmentBootstrapStore enrollmentStore,
        DeviceEnrollmentCredentialIssuer credentialIssuer,
        Uri managementOrigin,
        TimeProvider? timeProvider = null,
        TimeSpan? credentialLifetime = null)
    {
        this.proofVerifier = proofVerifier ?? throw new ArgumentNullException(nameof(proofVerifier));
        this.replayStore = replayStore ?? throw new ArgumentNullException(nameof(replayStore));
        this.enrollmentStore = enrollmentStore ?? throw new ArgumentNullException(nameof(enrollmentStore));
        this.credentialIssuer = credentialIssuer ?? throw new ArgumentNullException(nameof(credentialIssuer));
        this.managementOrigin = DeviceEnrollmentCredential.NormalizeManagementOrigin(managementOrigin);
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.credentialLifetime = credentialLifetime ?? TimeSpan.FromDays(30);
        if (this.credentialLifetime < TimeSpan.FromHours(1) ||
            this.credentialLifetime > TimeSpan.FromDays(90))
        {
            throw new ArgumentOutOfRangeException(nameof(credentialLifetime));
        }
    }

    public async ValueTask<IssuedDeviceEnrollmentCredential> EnrollAsync(
        SignedDeviceEnrollmentProof proof,
        EnrollmentBootstrapToken bootstrapToken,
        CancellationToken cancellationToken = default)
    {
        var verified = proofVerifier.Verify(proof, bootstrapToken, managementOrigin);
        var now = timeProvider.GetUtcNow();
        if (!await replayStore.TryReserveAsync(
                verified.DeviceId,
                verified.Nonce,
                now,
                TimeSpan.FromMinutes(15),
                cancellationToken).ConfigureAwait(false))
        {
            throw new DeviceManagementException("The enrollment request nonce was already used.");
        }

        var enrollment = await enrollmentStore.EnrollAsync(
            bootstrapToken,
            verified,
            managementOrigin,
            now,
            credentialLifetime,
            cancellationToken).ConfigureAwait(false) ??
            throw new DeviceManagementException(
                "The enrollment bootstrap credential is unavailable or expired.");
        return credentialIssuer.Issue(enrollment);
    }
}
