using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed record VerifiedDeviceEnrollmentCredential(
    DeviceEnrollmentCredential Credential,
    string CredentialSha256);
