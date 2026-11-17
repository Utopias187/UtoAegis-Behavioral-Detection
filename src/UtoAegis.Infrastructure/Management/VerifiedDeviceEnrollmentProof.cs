namespace UtoAegis.Infrastructure.Management;

public sealed record VerifiedDeviceEnrollmentProof(
    string DeviceId,
    string PublicKeySpkiBase64,
    string PublicKeySha256,
    DateTimeOffset TimestampUtc,
    string Nonce);
