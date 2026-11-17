using System.Text.Json;

namespace UtoAegis.Core.Management;

public sealed record FleetHealthSnapshot
{
    public const int CurrentProtocolVersion = 1;
    public const int MaximumErrorCodeCount = 16;
    public const int MaximumErrorCodeLength = 64;

    public FleetHealthSnapshot(
        string deviceId,
        string enrollmentId,
        string agentVersion,
        RolloutRing rolloutRing,
        string policyId,
        long policySequence,
        string manifestSha256,
        PolicyVerificationState policyVerification,
        FleetComponentState monitor,
        FleetComponentState updater,
        FleetComponentState telemetry,
        FleetComponentState guard,
        DateTimeOffset observedUtc,
        DateTimeOffset? lastSuccessfulContactUtc,
        IReadOnlyCollection<string> errorCodes)
    {
        ArgumentNullException.ThrowIfNull(rolloutRing);
        ArgumentNullException.ThrowIfNull(errorCodes);
        ArgumentOutOfRangeException.ThrowIfNegative(policySequence);
        ValidateEnum(policyVerification, nameof(policyVerification));
        ValidateEnum(monitor, nameof(monitor));
        ValidateEnum(updater, nameof(updater));
        ValidateEnum(telemetry, nameof(telemetry));
        ValidateEnum(guard, nameof(guard));
        ArgumentOutOfRangeException.ThrowIfEqual(observedUtc, default, nameof(observedUtc));
        var observed = observedUtc.ToUniversalTime();
        var lastContact = lastSuccessfulContactUtc?.ToUniversalTime();
        if (lastContact > observed)
        {
            throw new ArgumentException(
                "The last successful contact cannot be later than the observation.",
                nameof(lastSuccessfulContactUtc));
        }

        if (errorCodes.Count > MaximumErrorCodeCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(errorCodes),
                $"Fleet health may contain at most {MaximumErrorCodeCount} error codes.");
        }

        var normalizedErrors = errorCodes.Select(ValidateErrorCode)
            .OrderBy(code => code, StringComparer.Ordinal)
            .ToArray();
        if (normalizedErrors.Distinct(StringComparer.Ordinal).Count() != normalizedErrors.Length)
        {
            throw new ArgumentException("Fleet health error codes must be unique.", nameof(errorCodes));
        }

        ProtocolVersion = CurrentProtocolVersion;
        DeviceId = DeviceIdentityState.ValidateHex(deviceId, 32, nameof(deviceId));
        EnrollmentId = DeviceIdentityState.ValidateIdentifier(
            enrollmentId,
            128,
            nameof(enrollmentId));
        AgentVersion = DeviceIdentityState.ValidateIdentifier(
            agentVersion,
            64,
            nameof(agentVersion));
        RolloutRing = rolloutRing;
        PolicyId = policySequence == 0
            ? ValidateUnavailablePolicy(policyId, nameof(policyId))
            : DeviceIdentityState.ValidateIdentifier(policyId, 64, nameof(policyId));
        PolicySequence = policySequence;
        ManifestSha256 = policySequence == 0
            ? ValidateUnavailablePolicy(manifestSha256, nameof(manifestSha256))
            : DeviceIdentityState.ValidateHex(manifestSha256, 64, nameof(manifestSha256));
        PolicyVerification = policyVerification;
        Monitor = monitor;
        Updater = updater;
        Telemetry = telemetry;
        Guard = guard;
        ObservedUtc = observed;
        LastSuccessfulContactUtc = lastContact;
        ErrorCodes = normalizedErrors;
    }

    public int ProtocolVersion { get; }
    public string DeviceId { get; }
    public string EnrollmentId { get; }
    public string AgentVersion { get; }
    public RolloutRing RolloutRing { get; }
    public string PolicyId { get; }
    public long PolicySequence { get; }
    public string ManifestSha256 { get; }
    public PolicyVerificationState PolicyVerification { get; }
    public FleetComponentState Monitor { get; }
    public FleetComponentState Updater { get; }
    public FleetComponentState Telemetry { get; }
    public FleetComponentState Guard { get; }
    public DateTimeOffset ObservedUtc { get; }
    public DateTimeOffset? LastSuccessfulContactUtc { get; }
    public IReadOnlyList<string> ErrorCodes { get; }

    public byte[] GetCanonicalBytes()
    {
        using var stream = new MemoryStream(1024);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("protocolVersion", ProtocolVersion);
            writer.WriteString("deviceId", DeviceId);
            writer.WriteString("enrollmentId", EnrollmentId);
            writer.WriteString("agentVersion", AgentVersion);
            writer.WriteString("rolloutRing", RolloutRing.Value);
            writer.WriteString("policyId", PolicyId);
            writer.WriteNumber("policySequence", PolicySequence);
            writer.WriteString("manifestSha256", ManifestSha256);
            writer.WriteString("policyVerification", PolicyVerification.ToString());
            writer.WriteString("monitor", Monitor.ToString());
            writer.WriteString("updater", Updater.ToString());
            writer.WriteString("telemetry", Telemetry.ToString());
            writer.WriteString("guard", Guard.ToString());
            writer.WriteString("observedUtc", ObservedUtc.ToString("O"));
            if (LastSuccessfulContactUtc is null)
            {
                writer.WriteNull("lastSuccessfulContactUtc");
            }
            else
            {
                writer.WriteString(
                    "lastSuccessfulContactUtc",
                    LastSuccessfulContactUtc.Value.ToString("O"));
            }

            writer.WriteStartArray("errorCodes");
            foreach (var errorCode in ErrorCodes)
            {
                writer.WriteStringValue(errorCode);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static void ValidateEnum<T>(T value, string parameterName) where T : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }
    }

    private static string ValidateErrorCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var normalized = value.Trim().ToUpperInvariant();
        if (normalized.Length > MaximumErrorCodeLength ||
            !char.IsAsciiLetterOrDigit(normalized[0]) ||
            !char.IsAsciiLetterOrDigit(normalized[^1]) ||
            normalized.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_'))
        {
            throw new ArgumentException(
                "Fleet health error codes must be bounded stable identifiers.",
                nameof(value));
        }

        return normalized;
    }

    private static string ValidateUnavailablePolicy(string value, string parameterName)
    {
        if (!string.IsNullOrEmpty(value))
        {
            throw new ArgumentException(
                "Policy identity and hash must be empty when no policy is active.",
                parameterName);
        }

        return string.Empty;
    }
}
