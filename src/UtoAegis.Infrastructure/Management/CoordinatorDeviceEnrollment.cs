using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed record CoordinatorDeviceEnrollment(
    string EnrollmentId,
    string DeviceId,
    string PublicKeySpkiBase64,
    string PublicKeySha256,
    RolloutRing RolloutRing,
    long CredentialSequence,
    DeviceEnrollmentStatus Status,
    long RevocationGeneration,
    DateTimeOffset IssuedUtc,
    DateTimeOffset ExpiresUtc,
    Uri ManagementOrigin);
