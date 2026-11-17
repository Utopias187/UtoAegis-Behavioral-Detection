using System.Security.Cryptography;
using System.Text;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.RuntimeIntegrity;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Management;

public sealed class SignedPolicyDistributionVerifier
{
    public const string PolicyDirectoryName = "policy";
    public const string AuthorizationFileName = "authorization.json";
    public const string AuthorizationSignatureFileName = "authorization.sig";
    public const int MaximumSignatureTextLength = 256;

    private readonly ThreatTrustStore policyTrustStore;
    private readonly SignedRuntimePolicyVerifier runtimePolicyVerifier;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan clockSkew;

    public SignedPolicyDistributionVerifier(
        ThreatTrustStore policyTrustStore,
        TimeProvider? timeProvider = null,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(policyTrustStore);
        this.clockSkew = clockSkew ?? TimeSpan.FromMinutes(5);
        if (this.clockSkew < TimeSpan.Zero || this.clockSkew > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkew));
        }

        this.policyTrustStore = policyTrustStore;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        runtimePolicyVerifier = new SignedRuntimePolicyVerifier(
            policyTrustStore,
            this.timeProvider,
            this.clockSkew);
    }

    public async ValueTask<VerifiedPolicyDistribution> VerifyAsync(
        string packagePath,
        VerifiedDeviceEnrollmentCredential enrollment,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
        ArgumentNullException.ThrowIfNull(enrollment);
        var fullPath = Path.GetFullPath(packagePath);
        var directory = new DirectoryInfo(fullPath);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new RuntimePolicyException(
                "The policy distribution package must be an existing regular directory.");
        }

        ValidatePackageContents(directory);
        var authorizationBytes = await ReadBoundedAsync(
            Path.Combine(fullPath, AuthorizationFileName),
            PolicyDistributionAuthorizationReader.MaximumAuthorizationLength,
            cancellationToken).ConfigureAwait(false);
        var signatureText = await ReadBoundedTextAsync(
            Path.Combine(fullPath, AuthorizationSignatureFileName),
            MaximumSignatureTextLength,
            cancellationToken).ConfigureAwait(false);
        var signature = ParseSignature(signatureText);
        var authorization = PolicyDistributionAuthorizationReader.Read(authorizationBytes);
        if (!policyTrustStore.TryGetKey(authorization.KeyId, out var key) || key is null)
        {
            throw new RuntimePolicyException(
                $"Policy authorization key '{authorization.KeyId}' is not trusted.");
        }

        if (!key.Verify(authorizationBytes, signature))
        {
            throw new RuntimePolicyException(
                "The policy distribution authorization signature is not valid.");
        }

        var now = timeProvider.GetUtcNow();
        ValidateAuthorizationTime(authorization, now);
        ValidateEnrollment(enrollment.Credential, authorization, now);

        var runtimePolicy = await runtimePolicyVerifier.VerifyAsync(
            Path.Combine(fullPath, PolicyDirectoryName),
            cancellationToken).ConfigureAwait(false);
        if (!string.Equals(
                authorization.PolicyId,
                runtimePolicy.Manifest.PolicyId,
                StringComparison.Ordinal) ||
            authorization.PolicySequence != runtimePolicy.Manifest.Sequence ||
            !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(authorization.ManifestSha256),
                Convert.FromHexString(runtimePolicy.ManifestSha256)))
        {
            throw new RuntimePolicyException(
                "The runtime policy does not match its signed distribution authorization.");
        }

        return new VerifiedPolicyDistribution(
            authorization,
            Convert.ToHexString(SHA256.HashData(authorizationBytes)).ToLowerInvariant(),
            runtimePolicy,
            fullPath);
    }

    private static void ValidatePackageContents(DirectoryInfo directory)
    {
        var entries = directory.EnumerateFileSystemInfos().ToArray();
        var policyDirectory = entries.SingleOrDefault(entry =>
            string.Equals(entry.Name, PolicyDirectoryName, StringComparison.Ordinal));
        if (entries.Length != 3 ||
            policyDirectory is not DirectoryInfo ||
            policyDirectory.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            entries.Where(entry => entry != policyDirectory).Any(entry =>
                entry is not FileInfo || entry.Attributes.HasFlag(FileAttributes.ReparsePoint)) ||
            !entries.Any(entry => string.Equals(
                entry.Name,
                AuthorizationFileName,
                StringComparison.Ordinal)) ||
            !entries.Any(entry => string.Equals(
                entry.Name,
                AuthorizationSignatureFileName,
                StringComparison.Ordinal)))
        {
            throw new RuntimePolicyException(
                "The policy distribution package must contain only a regular policy directory, authorization.json, and authorization.sig.");
        }
    }

    private void ValidateAuthorizationTime(
        PolicyDistributionAuthorization authorization,
        DateTimeOffset now)
    {
        if (authorization.IssuedUtc > now + clockSkew)
        {
            throw new RuntimePolicyException(
                "The policy distribution authorization is not valid yet.");
        }

        if (authorization.ExpiresUtc <= now - clockSkew)
        {
            throw new RuntimePolicyException(
                "The policy distribution authorization has expired.");
        }
    }

    private void ValidateEnrollment(
        DeviceEnrollmentCredential enrollment,
        PolicyDistributionAuthorization authorization,
        DateTimeOffset now)
    {
        if (enrollment.Status != DeviceEnrollmentStatus.Active)
        {
            throw new RuntimePolicyException(
                "Only an active device enrollment may accept distributed policy.");
        }

        if (enrollment.IssuedUtc > now + clockSkew || enrollment.ExpiresUtc <= now - clockSkew)
        {
            throw new RuntimePolicyException(
                "The device enrollment is outside its validity period.");
        }

        if (!authorization.AllowedRolloutRings.Any(ring =>
                string.Equals(ring.Value, enrollment.RolloutRing.Value, StringComparison.Ordinal)))
        {
            throw new RuntimePolicyException(
                $"Rollout ring '{enrollment.RolloutRing.Value}' is not authorized for this policy.");
        }
    }

    private static byte[] ParseSignature(string signatureText)
    {
        try
        {
            return Convert.FromBase64String(signatureText.Trim());
        }
        catch (FormatException exception)
        {
            throw new RuntimePolicyException(
                "The policy distribution authorization signature must contain base64 text.",
                exception);
        }
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
                $"Policy distribution file '{file.Name}' is missing, unsafe, empty, or oversized.");
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
                    $"Policy distribution file '{file.Name}' changed while it was read.");
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
                $"Policy distribution file '{file.Name}' could not be read.",
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
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new RuntimePolicyException(
                "The policy distribution authorization signature is not valid UTF-8.",
                exception);
        }
    }
}
