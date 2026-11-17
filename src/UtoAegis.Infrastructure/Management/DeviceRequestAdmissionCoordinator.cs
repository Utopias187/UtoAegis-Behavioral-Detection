using System.Security.Cryptography;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceRequestAdmissionCoordinator
{
    private readonly SqliteEnrollmentBootstrapStore enrollmentStore;
    private readonly SqliteDeviceRequestReplayStore replayStore;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan maximumAge;
    private readonly TimeSpan clockSkew;
    private readonly TimeSpan replayRetention;

    public DeviceRequestAdmissionCoordinator(
        SqliteEnrollmentBootstrapStore enrollmentStore,
        SqliteDeviceRequestReplayStore replayStore,
        TimeProvider? timeProvider = null,
        TimeSpan? maximumAge = null,
        TimeSpan? clockSkew = null,
        TimeSpan? replayRetention = null)
    {
        this.enrollmentStore = enrollmentStore ??
            throw new ArgumentNullException(nameof(enrollmentStore));
        this.replayStore = replayStore ?? throw new ArgumentNullException(nameof(replayStore));
        this.maximumAge = maximumAge ?? TimeSpan.FromMinutes(5);
        this.clockSkew = clockSkew ?? TimeSpan.FromMinutes(1);
        this.replayRetention = replayRetention ?? TimeSpan.FromMinutes(15);
        if (this.maximumAge <= TimeSpan.Zero || this.maximumAge > TimeSpan.FromMinutes(15))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAge));
        }

        if (this.clockSkew < TimeSpan.Zero || this.clockSkew > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkew));
        }

        if (this.replayRetention < TimeSpan.FromMinutes(1) ||
            this.replayRetention > TimeSpan.FromHours(24) ||
            this.replayRetention < this.maximumAge + this.clockSkew)
        {
            throw new ArgumentOutOfRangeException(
                nameof(replayRetention),
                "Replay retention must cover the complete request validity window and be no longer than 24 hours.");
        }

        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<AuthenticatedDeviceRequest> AuthenticateAsync(
        SignedDeviceRequest request,
        string expectedMethod,
        string expectedPathAndQuery,
        ReadOnlyMemory<byte> expectedBody,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var enrollment = await enrollmentStore.GetEnrollmentAsync(
            request.Payload.EnrollmentId,
            cancellationToken).ConfigureAwait(false) ??
            throw new DeviceManagementException("The device request is not authorized.");
        var now = timeProvider.GetUtcNow();
        if (!string.Equals(
                request.Payload.DeviceId,
                enrollment.DeviceId,
                StringComparison.Ordinal) ||
            request.Payload.CredentialSequence != enrollment.CredentialSequence ||
            enrollment.Status != DeviceEnrollmentStatus.Active ||
            enrollment.ExpiresUtc <= now - clockSkew ||
            request.Payload.TimestampUtc > now + clockSkew ||
            request.Payload.TimestampUtc < now - maximumAge - clockSkew)
        {
            throw new DeviceManagementException("The device request is not authorized.");
        }

        VerifySignature(
            enrollment,
            request,
            expectedMethod,
            expectedPathAndQuery,
            expectedBody.Span);
        if (!await replayStore.TryReserveAsync(
                enrollment.DeviceId,
                request.Payload.Nonce,
                now,
                replayRetention,
                cancellationToken).ConfigureAwait(false))
        {
            throw new DeviceManagementException(
                "The device request nonce was already used or cannot be retained safely.");
        }

        return new AuthenticatedDeviceRequest(
            enrollment,
            now,
            request.Payload.Method,
            request.Payload.PathAndQuery,
            request.Payload.BodySha256);
    }

    private static void VerifySignature(
        CoordinatorDeviceEnrollment enrollment,
        SignedDeviceRequest request,
        string expectedMethod,
        string expectedPathAndQuery,
        ReadOnlySpan<byte> expectedBody)
    {
        try
        {
            var publicKeyBytes = Convert.FromBase64String(enrollment.PublicKeySpkiBase64);
            if (!CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(publicKeyBytes),
                    Convert.FromHexString(enrollment.PublicKeySha256)))
            {
                throw new DeviceManagementException("The stored device public key is invalid.");
            }

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeyBytes, out var bytesRead);
            if (bytesRead != publicKeyBytes.Length || key.KeySize != 256 ||
                !new DeviceRequestSignatureVerifier(key).Verify(
                    request,
                    expectedMethod,
                    expectedPathAndQuery,
                    expectedBody))
            {
                throw new DeviceManagementException(
                    "The device request signature or exact request binding is invalid.");
            }
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            throw new DeviceManagementException(
                "The stored device public key is invalid.",
                exception);
        }
    }
}
