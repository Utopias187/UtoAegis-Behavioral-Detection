using System.Text.Json;
using System.Text.Json.Serialization;

namespace UtoAegis.Guard;

internal sealed record GuardConfiguration(
    string PolicyBundlePath,
    string PolicyStatePath,
    IReadOnlyDictionary<string, string> TrustedSigningKeyPaths,
    string RecoveryStatePath,
    string SecurityTelemetrySpoolPath,
    string DeploymentId,
    int TelemetryMaximumRecords)
{
    private const int MaximumConfigurationLength = 256 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        MaxDepth = 8,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static GuardConfiguration Load(string configurationPath, string baseDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        var fullConfigurationPath = Path.GetFullPath(configurationPath);
        var file = new FileInfo(fullConfigurationPath);
        file.Refresh();
        if (!file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            file.Length is <= 0 or > MaximumConfigurationLength)
        {
            throw new GuardConfigurationException(
                "The integrity guard configuration is missing, unsafe, empty, or oversized.");
        }

        try
        {
            var document = JsonSerializer.Deserialize<ConfigurationDocument>(
                File.ReadAllBytes(fullConfigurationPath),
                SerializerOptions)?.UtoAegisGuard ??
                throw new GuardConfigurationException(
                    "The integrity guard configuration section is missing.");
            var resolvedBase = Path.GetFullPath(baseDirectory);
            var bundlePath = RequiredPath(document.PolicyBundlePath, "PolicyBundlePath", resolvedBase);
            EnsureRegularDirectory(bundlePath, "PolicyBundlePath");
            var policyStatePath = RequiredPath(document.PolicyStatePath, "PolicyStatePath", resolvedBase);
            var recoveryStatePath = RequiredPath(
                document.RecoveryStatePath,
                "RecoveryStatePath",
                resolvedBase);
            var telemetryPath = RequiredPath(
                document.SecurityTelemetrySpoolPath,
                "SecurityTelemetrySpoolPath",
                resolvedBase);
            EnsureRegularDirectoryIfPresent(telemetryPath, "SecurityTelemetrySpoolPath");
            var deploymentId = RequiredIdentifier(document.DeploymentId, "DeploymentId");
            var maximumRecords = document.TelemetryMaximumRecords ?? 10_000;
            if (maximumRecords is < 1 or > 1_000_000)
            {
                throw new GuardConfigurationException(
                    "TelemetryMaximumRecords must be from 1 through 1000000.");
            }

            var keyDocuments = document.TrustedSigningKeys ?? [];
            if (keyDocuments.Count is 0 or > 32)
            {
                throw new GuardConfigurationException(
                    "TrustedSigningKeys must contain 1 through 32 entries.");
            }

            var keys = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var key in keyDocuments)
            {
                var keyId = RequiredIdentifier(key.KeyId, "TrustedSigningKeys:KeyId");
                var keyPath = RequiredPath(
                    key.PublicKeyPath,
                    "TrustedSigningKeys:PublicKeyPath",
                    resolvedBase);
                EnsureRegularFile(keyPath, $"trusted signing key '{keyId}'");
                if (!keys.TryAdd(keyId, keyPath))
                {
                    throw new GuardConfigurationException(
                        $"Trusted signing key id '{keyId}' is duplicated.");
                }
            }

            foreach (var statePath in new[] { policyStatePath, recoveryStatePath })
            {
                var parent = Path.GetDirectoryName(statePath)!;
                if (PathEquals(parent, Path.GetPathRoot(parent)!) ||
                    IsWithin(resolvedBase, parent) || IsWithin(bundlePath, parent))
                {
                    throw new GuardConfigurationException(
                        "Guard state must be outside the installation and policy bundle and not at a filesystem root.");
                }
            }

            if (PathEquals(policyStatePath, recoveryStatePath) ||
                PathEquals(telemetryPath, Path.GetDirectoryName(policyStatePath)!) ||
                IsWithin(telemetryPath, policyStatePath) ||
                IsWithin(telemetryPath, recoveryStatePath) ||
                IsWithin(resolvedBase, telemetryPath) ||
                IsWithin(bundlePath, telemetryPath))
            {
                throw new GuardConfigurationException(
                    "Policy state, recovery state, telemetry, installation, and policy paths must be isolated.");
            }

            if (keys.Values.Any(path =>
                    IsWithin(telemetryPath, path) ||
                    IsWithin(Path.GetDirectoryName(policyStatePath)!, path) ||
                    IsWithin(Path.GetDirectoryName(recoveryStatePath)!, path) ||
                    IsWithin(bundlePath, path)))
            {
                throw new GuardConfigurationException(
                    "Trusted signing keys must be outside writable guard state, telemetry, and policy bundle paths.");
            }

            return new GuardConfiguration(
                bundlePath,
                policyStatePath,
                keys,
                recoveryStatePath,
                telemetryPath,
                deploymentId,
                maximumRecords);
        }
        catch (GuardConfigurationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException or IOException or UnauthorizedAccessException or
                ArgumentException or NotSupportedException)
        {
            throw new GuardConfigurationException(
                "The integrity guard configuration is invalid.",
                exception);
        }
    }

    private static string RequiredPath(string? value, string name, string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new GuardConfigurationException($"UtoAegisGuard:{name} is required.");
        }

        return Path.GetFullPath(Environment.ExpandEnvironmentVariables(value.Trim()), baseDirectory);
    }

    private static string RequiredIdentifier(string? value, string name)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Length > 64 ||
            !char.IsAsciiLetterOrDigit(normalized[0]) ||
            !char.IsAsciiLetterOrDigit(normalized[^1]) ||
            normalized.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_'))
        {
            throw new GuardConfigurationException(
                $"UtoAegisGuard:{name} must use 1 to 64 path-safe ASCII characters.");
        }

        return normalized;
    }

    private static void EnsureRegularDirectory(string path, string name)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new GuardConfigurationException(
                $"UtoAegisGuard:{name} must reference an existing regular directory.");
        }
    }

    private static void EnsureRegularDirectoryIfPresent(string path, string name)
    {
        if (File.Exists(path) ||
            (Directory.Exists(path) && File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint)))
        {
            throw new GuardConfigurationException(
                $"UtoAegisGuard:{name} must reference a regular directory path.");
        }
    }

    private static void EnsureRegularFile(string path, string name)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (!file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new GuardConfigurationException($"{name} must reference an existing regular file.");
        }
    }

    private static bool IsWithin(string root, string candidate)
    {
        var relative = Path.GetRelativePath(root, candidate);
        return relative == "." ||
            (!Path.IsPathRooted(relative) && relative != ".." &&
             !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
             !relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal));
    }

    private static bool PathEquals(string first, string second) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(first),
            Path.TrimEndingDirectorySeparator(second),
            OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal);

    private sealed record ConfigurationDocument(GuardDocument? UtoAegisGuard);

    private sealed record GuardDocument(
        string? PolicyBundlePath,
        string? PolicyStatePath,
        IReadOnlyList<SigningKeyDocument>? TrustedSigningKeys,
        string? RecoveryStatePath,
        string? SecurityTelemetrySpoolPath,
        string? DeploymentId,
        int? TelemetryMaximumRecords);

    private sealed record SigningKeyDocument(string? KeyId, string? PublicKeyPath);
}
