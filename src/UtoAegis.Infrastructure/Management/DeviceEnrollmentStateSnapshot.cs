using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed record DeviceEnrollmentStateSnapshot(
    long CredentialSequence,
    string CredentialSha256,
    string EnrollmentId,
    string DeviceId,
    string PublicKeySha256,
    string RolloutRing,
    DeviceEnrollmentStatus Status,
    long RevocationGeneration,
    DateTimeOffset ExpiresUtc,
    string ManagementOrigin);
