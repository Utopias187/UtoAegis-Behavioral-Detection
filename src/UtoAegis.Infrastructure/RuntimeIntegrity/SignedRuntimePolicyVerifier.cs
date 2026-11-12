using System.Security.Cryptography;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.RuntimeIntegrity;

public sealed class SignedRuntimePolicyVerifier
{
    public const string ManifestFileName = "policy.json";
    public const string SignatureFileName = "policy.sig";
    public const int MaximumSignatureTextLength = 256;

    private readonly ThreatTrustStore trustStore;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan clockSkew;

    public SignedRuntimePolicyVerifier(
        ThreatTrustStore trustStore,
        TimeProvider? timeProvider = null,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(trustStore);
        var skew = clockSkew ?? TimeSpan.FromMinutes(5);
        if (skew < TimeSpan.Zero || skew > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkew));
        }

        this.trustStore = trustStore;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.clockSkew = skew;
    }

    public async ValueTask<VerifiedRuntimePolicy> VerifyAsync(
        string bundlePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundlePath);
        var fullPath = Path.GetFullPath(bundlePath);
        var directory = new DirectoryInfo(fullPath);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new RuntimePolicyException(
                "The runtime policy bundle must be an existing regular directory.");
        }

        var files = directory.EnumerateFileSystemInfos().ToArray();
        if (files.Length != 2 || files.Any(entry =>
                entry is not FileInfo || entry.Attributes.HasFlag(FileAttributes.ReparsePoint)) ||
            !files.Any(entry => string.Equals(entry.Name, ManifestFileName, StringComparison.Ordinal)) ||
            !files.Any(entry => string.Equals(entry.Name, SignatureFileName, StringComparison.Ordinal)))
        {
            throw new RuntimePolicyException(
                "The runtime policy bundle must contain only policy.json and policy.sig as regular files.");
        }

        var manifestBytes = await ReadBoundedAsync(
            Path.Combine(fullPath, ManifestFileName),
            RuntimePolicyReader.MaximumManifestLength,
            cancellationToken).ConfigureAwait(false);
        var signatureText = await ReadBoundedTextAsync(
            Path.Combine(fullPath, SignatureFileName),
            MaximumSignatureTextLength,
            cancellationToken).ConfigureAwait(false);
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(signatureText.Trim());
        }
        catch (FormatException exception)
        {
            throw new RuntimePolicyException(
                "The runtime policy signature must contain base64 text.",
                exception);
        }

        var manifest = RuntimePolicyReader.Read(manifestBytes);
        if (!trustStore.TryGetKey(manifest.KeyId, out var key) || key is null)
        {
            throw new RuntimePolicyException(
                $"Runtime policy signing key '{manifest.KeyId}' is not trusted.");
        }

        if (!key.Verify(manifestBytes, signature))
        {
            throw new RuntimePolicyException("The runtime policy signature is not valid.");
        }

        var now = timeProvider.GetUtcNow();
        if (manifest.IssuedUtc > now + clockSkew)
        {
            throw new RuntimePolicyException("The runtime policy is not valid yet.");
        }

        if (manifest.ExpiresUtc <= now - clockSkew)
        {
            throw new RuntimePolicyException("The runtime policy has expired.");
        }

        return new VerifiedRuntimePolicy(
            manifest,
            Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant(),
            fullPath);
    }

    private static async ValueTask<byte[]> ReadBoundedAsync(
        string path,
        int maximumLength,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (!file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            file.Length is <= 0 || file.Length > maximumLength)
        {
            throw new RuntimePolicyException(
                $"Runtime policy file '{file.Name}' is missing, unsafe, empty, or oversized.");
        }

        try
        {
            var bytes = new byte[checked((int)file.Length)];
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            if (stream.ReadByte() != -1)
            {
                throw new RuntimePolicyException(
                    $"Runtime policy file '{file.Name}' changed while it was read.");
            }

            return bytes;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (RuntimePolicyException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new RuntimePolicyException(
                $"Runtime policy file '{file.Name}' could not be read.",
                exception);
        }
    }

    private static async ValueTask<string> ReadBoundedTextAsync(
        string path,
        int maximumLength,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedAsync(path, maximumLength, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return new System.Text.UTF8Encoding(false, true).GetString(bytes);
        }
        catch (System.Text.DecoderFallbackException exception)
        {
            throw new RuntimePolicyException(
                "The runtime policy signature is not valid UTF-8.",
                exception);
        }
    }
}
