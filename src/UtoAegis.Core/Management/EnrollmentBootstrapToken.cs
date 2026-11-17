using System.Security.Cryptography;

namespace UtoAegis.Core.Management;

public sealed class EnrollmentBootstrapToken : IDisposable
{
    public const int SecretLength = 32;
    public const int EncodedLength = 43;

    private byte[] secret;
    private bool disposed;

    private EnrollmentBootstrapToken(byte[] secret)
    {
        this.secret = secret;
    }

    public static EnrollmentBootstrapToken Generate() => new(RandomNumberGenerator.GetBytes(SecretLength));

    public static EnrollmentBootstrapToken Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length != EncodedLength || value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            throw new ArgumentException(
                "An enrollment bootstrap token must be canonical base64url text.",
                nameof(value));
        }

        try
        {
            var bytes = Convert.FromBase64String(
                value.Replace('-', '+').Replace('_', '/') + "=");
            if (bytes.Length != SecretLength ||
                !string.Equals(Encode(bytes), value, StringComparison.Ordinal))
            {
                CryptographicOperations.ZeroMemory(bytes);
                throw new ArgumentException(
                    "An enrollment bootstrap token must contain 256 random bits.",
                    nameof(value));
            }

            return new EnrollmentBootstrapToken(bytes);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "An enrollment bootstrap token must be canonical base64url text.",
                nameof(value),
                exception);
        }
    }

    public string Reveal()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return Encode(secret);
    }

    public string ComputeSha256()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return Convert.ToHexString(SHA256.HashData(secret)).ToLowerInvariant();
    }

    public override string ToString() => "[redacted enrollment bootstrap token]";

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(secret);
        secret = [];
        disposed = true;
        GC.SuppressFinalize(this);
    }

    private static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
