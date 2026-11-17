namespace UtoAegis.Infrastructure.Management;

public sealed record AuthenticatedDeviceRequest(
    CoordinatorDeviceEnrollment Enrollment,
    DateTimeOffset AuthenticatedUtc,
    string Method,
    string PathAndQuery,
    string BodySha256);
