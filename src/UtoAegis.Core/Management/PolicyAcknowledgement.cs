using System.Text.Json;

namespace UtoAegis.Core.Management;

public sealed record PolicyAcknowledgement
{
    public const int CurrentSchemaVersion = 1;

    public PolicyAcknowledgement(
        string acknowledgementId,
        string deviceId,
        string enrollmentId,
        string policyId,
        long policySequence,
        string manifestSha256,
        DateTimeOffset appliedUtc)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(policySequence);
        ArgumentOutOfRangeException.ThrowIfEqual(appliedUtc, default, nameof(appliedUtc));
        SchemaVersion = CurrentSchemaVersion;
        AcknowledgementId = DeviceIdentityState.ValidateHex(
            acknowledgementId,
            32,
            nameof(acknowledgementId));
        DeviceId = DeviceIdentityState.ValidateHex(deviceId, 32, nameof(deviceId));
        EnrollmentId = DeviceIdentityState.ValidateIdentifier(
            enrollmentId,
            128,
            nameof(enrollmentId));
        PolicyId = DeviceIdentityState.ValidateIdentifier(policyId, 64, nameof(policyId));
        PolicySequence = policySequence;
        ManifestSha256 = DeviceIdentityState.ValidateHex(
            manifestSha256,
            64,
            nameof(manifestSha256));
        AppliedUtc = appliedUtc.ToUniversalTime();
    }

    public int SchemaVersion { get; }

    public string AcknowledgementId { get; }

    public string DeviceId { get; }

    public string EnrollmentId { get; }

    public string PolicyId { get; }

    public long PolicySequence { get; }

    public string ManifestSha256 { get; }

    public DateTimeOffset AppliedUtc { get; }

    public byte[] GetCanonicalBytes()
    {
        using var stream = new MemoryStream(512);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", SchemaVersion);
            writer.WriteString("acknowledgementId", AcknowledgementId);
            writer.WriteString("deviceId", DeviceId);
            writer.WriteString("enrollmentId", EnrollmentId);
            writer.WriteString("policyId", PolicyId);
            writer.WriteNumber("policySequence", PolicySequence);
            writer.WriteString("manifestSha256", ManifestSha256);
            writer.WriteString("appliedUtc", AppliedUtc.ToString("O"));
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}
