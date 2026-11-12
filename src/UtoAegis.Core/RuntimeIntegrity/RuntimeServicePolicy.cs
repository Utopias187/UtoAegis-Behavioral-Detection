using UtoAegis.Core.Reputation;

namespace UtoAegis.Core.RuntimeIntegrity;

public sealed record RuntimeServicePolicy
{
    public RuntimeServicePolicy(
        string name,
        string executablePath,
        string executableSha256,
        string account,
        RuntimeServiceStartMode startMode,
        bool recover)
    {
        Name = ValidateIdentifier(name, nameof(name));
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ExecutablePath = Path.GetFullPath(executablePath);
        if (!MalwareHashIndicator.TryNormalizeSha256(executableSha256, out var normalizedHash))
        {
            throw new ArgumentException(
                "The expected executable SHA-256 must contain 64 hexadecimal characters.",
                nameof(executableSha256));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(account);
        var normalizedAccount = account.Trim();
        if (normalizedAccount.Length > 256 || normalizedAccount.Any(char.IsControl))
        {
            throw new ArgumentException("The service account is not valid.", nameof(account));
        }

        if (!Enum.IsDefined(startMode))
        {
            throw new ArgumentOutOfRangeException(nameof(startMode));
        }

        ExecutableSha256 = normalizedHash!;
        Account = normalizedAccount;
        StartMode = startMode;
        Recover = recover;
    }

    public string Name { get; }

    public string ExecutablePath { get; }

    public string ExecutableSha256 { get; }

    public string Account { get; }

    public RuntimeServiceStartMode StartMode { get; }

    public bool Recover { get; }

    private static string ValidateIdentifier(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > 80 ||
            !char.IsAsciiLetterOrDigit(normalized[0]) ||
            !char.IsAsciiLetterOrDigit(normalized[^1]) ||
            normalized.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_'))
        {
            throw new ArgumentException(
                "Service names must use 1 to 80 path-safe ASCII characters.",
                parameterName);
        }

        return normalized;
    }
}
