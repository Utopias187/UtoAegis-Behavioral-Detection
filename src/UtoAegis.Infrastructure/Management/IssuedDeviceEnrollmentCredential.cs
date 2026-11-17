namespace UtoAegis.Infrastructure.Management;

public sealed record IssuedDeviceEnrollmentCredential(
    ReadOnlyMemory<byte> CredentialBytes,
    string SignatureBase64,
    CoordinatorDeviceEnrollment Enrollment);
