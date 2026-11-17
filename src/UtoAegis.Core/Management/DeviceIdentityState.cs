namespace UtoAegis.Core.Management;

public sealed record DeviceIdentityState
{
    public const int CurrentSchemaVersion = 1;

    public DeviceIdentityState(
        string deviceId,
        string keyName,
        string publicKeySha256,
        DateTimeOffset createdUtc)
    {
        DeviceId = ValidateHex(deviceId, 32, nameof(deviceId));
        KeyName = ValidateIdentifier(keyName, 128, nameof(keyName));
        PublicKeySha256 = ValidateHex(publicKeySha256, 64, nameof(publicKeySha256));
        ArgumentOutOfRangeException.ThrowIfEqual(createdUtc, default, nameof(createdUtc));

        SchemaVersion = CurrentSchemaVersion;
        CreatedUtc = createdUtc.ToUniversalTime();
    }

    public int SchemaVersion { get; }

    public string DeviceId { get; }

    public string KeyName { get; }

    public string PublicKeySha256 { get; }

    public DateTimeOffset CreatedUtc { get; }

    public static DeviceIdentityState Create(
        string keyName,
        string publicKeySha256,
        TimeProvider? timeProvider = null) =>
        new(
            Guid.NewGuid().ToString("N"),
            keyName,
            publicKeySha256,
            (timeProvider ?? TimeProvider.System).GetUtcNow());

    internal static string ValidateIdentifier(string value, int maximumLength, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > maximumLength ||
            !char.IsAsciiLetterOrDigit(normalized[0]) ||
            !char.IsAsciiLetterOrDigit(normalized[^1]) ||
            normalized.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_' and not ':'))
        {
            throw new ArgumentException(
                $"The value must use 1 to {maximumLength} safe ASCII characters.",
                parameterName);
        }

        return normalized;
    }

    internal static string ValidateHex(string value, int length, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length != length || value.Any(character =>
                !char.IsAsciiDigit(character) &&
                character is not (>= 'a' and <= 'f') and not (>= 'A' and <= 'F')))
        {
            throw new ArgumentException(
                $"The value must contain exactly {length} hexadecimal characters.",
                parameterName);
        }

        return value.ToLowerInvariant();
    }
}
