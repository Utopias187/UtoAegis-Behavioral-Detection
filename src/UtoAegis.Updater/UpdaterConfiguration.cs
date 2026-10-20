using System.Globalization;
using Microsoft.Extensions.Configuration;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Updater;

public sealed class UpdaterConfiguration
{
    public static readonly TimeSpan MinimumPollInterval = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan MaximumPollInterval = TimeSpan.FromDays(1);
    public static readonly TimeSpan MinimumRequestTimeout = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan MaximumRequestTimeout = TimeSpan.FromMinutes(10);

    private UpdaterConfiguration(
        Uri channelBaseUri,
        string contentStorePath,
        string downloadPath,
        string telemetryPath,
        string deploymentId,
        string rolloutRing,
        TimeSpan pollInterval,
        TimeSpan requestTimeout,
        int maximumRetainedVersions,
        UpdaterRetryPolicy retryPolicy,
        IReadOnlyList<UpdaterSigningKeyPolicy> signingKeys)
    {
        ChannelBaseUri = channelBaseUri;
        ContentStorePath = contentStorePath;
        DownloadPath = downloadPath;
        TelemetryPath = telemetryPath;
        DeploymentId = deploymentId;
        RolloutRing = rolloutRing;
        PollInterval = pollInterval;
        RequestTimeout = requestTimeout;
        MaximumRetainedVersions = maximumRetainedVersions;
        RetryPolicy = retryPolicy;
        SigningKeys = signingKeys;
    }

    public Uri ChannelBaseUri { get; }

    public string ContentStorePath { get; }

    public string DownloadPath { get; }

    public string TelemetryPath { get; }

    public string DeploymentId { get; }

    public string RolloutRing { get; }

    public TimeSpan PollInterval { get; }

    public TimeSpan RequestTimeout { get; }

    public int MaximumRetainedVersions { get; }

    public UpdaterRetryPolicy RetryPolicy { get; }

    public IReadOnlyList<UpdaterSigningKeyPolicy> SigningKeys { get; }

    public IReadOnlyDictionary<string, string> TrustedSigningKeyPaths => SigningKeys
        .Where(key => key.Status == UpdaterSigningKeyStatus.Trusted)
        .ToDictionary(key => key.KeyId, key => key.PublicKeyPath, StringComparer.Ordinal);

    public IReadOnlyCollection<string> RevokedSigningKeyIds => SigningKeys
        .Where(key => key.Status == UpdaterSigningKeyStatus.Revoked)
        .Select(key => key.KeyId)
        .ToArray();

    public static UpdaterConfiguration Load(
        IConfiguration configuration,
        string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        var section = configuration.GetSection("UtoAegisUpdater");

        try
        {
            var channelText = section["ChannelBaseUri"]?.Trim();
            if (!Uri.TryCreate(channelText, UriKind.Absolute, out var channelBaseUri))
            {
                throw new UpdaterConfigurationException(
                    "UtoAegisUpdater:ChannelBaseUri must be an absolute URI.");
            }

            RemoteThreatBundleDownloader.ValidateChannelUri(channelBaseUri);
            var resolvedBase = Path.GetFullPath(baseDirectory);
            var contentStorePath = RequiredDirectory(
                section,
                "ContentStorePath",
                resolvedBase);
            var downloadPath = RequiredDirectory(
                section,
                "DownloadPath",
                resolvedBase);
            var telemetryPath = RequiredFilePath(
                section,
                "TelemetryPath",
                resolvedBase);
            var telemetryDirectory = Path.GetDirectoryName(telemetryPath)!;
            EnsureRegularDirectory(telemetryDirectory, "TelemetryPath directory");

            var writableDirectories = new[]
            {
                contentStorePath,
                downloadPath,
                telemetryDirectory
            };
            if (writableDirectories.Any(path =>
                    PathEquals(path, Path.GetPathRoot(path)!) ||
                    IsWithin(path, resolvedBase) ||
                    IsWithin(resolvedBase, path)) ||
                writableDirectories.Distinct(PathComparer).Count() != writableDirectories.Length ||
                writableDirectories.Any(first => writableDirectories.Any(second =>
                    !PathEquals(first, second) && IsWithin(first, second))))
            {
                throw new UpdaterConfigurationException(
                    "Updater writable directories must be distinct, non-nested, outside the installation, and not filesystem roots.");
            }

            var signingKeys = ReadSigningKeys(
                section.GetSection("SigningKeys"),
                resolvedBase,
                writableDirectories);
            if (!signingKeys.Any(key => key.Status == UpdaterSigningKeyStatus.Trusted))
            {
                throw new UpdaterConfigurationException(
                    "At least one signing key must have Trusted status.");
            }

            var deploymentId = RequiredIdentifier(section, "DeploymentId");
            var rolloutRing = RequiredIdentifier(section, "RolloutRing");
            var pollInterval = TimeSpan.FromSeconds(ReadInt(
                section,
                "PollIntervalSeconds",
                defaultValue: 3600));
            if (pollInterval < MinimumPollInterval || pollInterval > MaximumPollInterval)
            {
                throw new UpdaterConfigurationException(
                    "PollIntervalSeconds must be from 60 through 86400.");
            }

            var requestTimeout = TimeSpan.FromSeconds(ReadInt(
                section,
                "RequestTimeoutSeconds",
                defaultValue: 120));
            if (requestTimeout < MinimumRequestTimeout || requestTimeout > MaximumRequestTimeout)
            {
                throw new UpdaterConfigurationException(
                    "RequestTimeoutSeconds must be from 5 through 600.");
            }

            var maximumRetainedVersions = ReadInt(
                section,
                "MaximumRetainedVersions",
                defaultValue: 3);
            if (maximumRetainedVersions is < 2 or > 64)
            {
                throw new UpdaterConfigurationException(
                    "MaximumRetainedVersions must be from 2 through 64.");
            }

            var retrySection = section.GetSection("Retry");
            var retryPolicy = new UpdaterRetryPolicy(
                ReadInt(retrySection, "MaximumAttempts", defaultValue: 4),
                TimeSpan.FromSeconds(ReadInt(
                    retrySection,
                    "InitialDelaySeconds",
                    defaultValue: 5)),
                TimeSpan.FromSeconds(ReadInt(
                    retrySection,
                    "MaximumDelaySeconds",
                    defaultValue: 300)));

            return new UpdaterConfiguration(
                channelBaseUri,
                contentStorePath,
                downloadPath,
                telemetryPath,
                deploymentId,
                rolloutRing,
                pollInterval,
                requestTimeout,
                maximumRetainedVersions,
                retryPolicy,
                signingKeys);
        }
        catch (UpdaterConfigurationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or
                PathTooLongException or UnauthorizedAccessException or IOException or OverflowException)
        {
            throw new UpdaterConfigurationException(
                "The UtoAegis updater configuration is invalid.",
                exception);
        }
    }

    private static List<UpdaterSigningKeyPolicy> ReadSigningKeys(
        IConfiguration section,
        string baseDirectory,
        IReadOnlyCollection<string> writableDirectories)
    {
        var keys = new List<UpdaterSigningKeyPolicy>();
        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        foreach (var child in section.GetChildren())
        {
            var keyId = child["KeyId"]?.Trim();
            var pathText = child["PublicKeyPath"];
            var statusText = child["Status"]?.Trim();
            if (string.IsNullOrWhiteSpace(keyId) ||
                string.IsNullOrWhiteSpace(pathText) ||
                !Enum.TryParse<UpdaterSigningKeyStatus>(
                    statusText,
                    ignoreCase: true,
                    out var status) ||
                !Enum.IsDefined(status))
            {
                throw new UpdaterConfigurationException(
                    "Every SigningKeys entry requires KeyId, PublicKeyPath, and Trusted or Revoked Status.");
            }

            ValidateIdentifier(keyId, "signing key ID");
            if (!identifiers.Add(keyId))
            {
                throw new UpdaterConfigurationException(
                    $"Signing key id '{keyId}' is duplicated.");
            }

            var path = ResolvePath(pathText, baseDirectory);
            EnsureRegularFile(path, $"Signing key '{keyId}'");
            if (writableDirectories.Any(directory => IsWithin(directory, path)))
            {
                throw new UpdaterConfigurationException(
                    "Signing keys must be outside updater-writable directories.");
            }

            keys.Add(new UpdaterSigningKeyPolicy(keyId, path, status));
            if (keys.Count > 32)
            {
                throw new UpdaterConfigurationException(
                    "At most 32 signing-key policies may be configured.");
            }
        }

        return keys;
    }

    private static string RequiredDirectory(
        IConfiguration section,
        string key,
        string baseDirectory)
    {
        var path = RequiredFilePath(section, key, baseDirectory);
        EnsureRegularDirectory(path, key);
        return path;
    }

    private static string RequiredFilePath(
        IConfiguration section,
        string key,
        string baseDirectory)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new UpdaterConfigurationException($"UtoAegisUpdater:{key} is required.");
        }

        return ResolvePath(value, baseDirectory);
    }

    private static string ResolvePath(string value, string baseDirectory)
    {
        var expanded = Environment.ExpandEnvironmentVariables(value.Trim());
        return Path.GetFullPath(expanded, baseDirectory);
    }

    private static string RequiredIdentifier(IConfiguration section, string key)
    {
        var value = section[key]?.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new UpdaterConfigurationException($"UtoAegisUpdater:{key} is required.");
        }

        ValidateIdentifier(value, key);
        return value;
    }

    private static void ValidateIdentifier(string value, string label)
    {
        if (value.Length > 64 ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            !char.IsAsciiLetterOrDigit(value[^1]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_'))
        {
            throw new UpdaterConfigurationException(
                $"The {label} must use 1 to 64 path-safe ASCII characters.");
        }
    }

    private static int ReadInt(
        IConfiguration section,
        string key,
        int defaultValue)
    {
        var text = section[key];
        if (string.IsNullOrWhiteSpace(text))
        {
            return defaultValue;
        }

        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            throw new UpdaterConfigurationException(
                $"UtoAegis updater value {key} must be an integer.");
        }

        return value;
    }

    private static void EnsureRegularDirectory(string path, string label)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new UpdaterConfigurationException(
                $"{label} must reference an existing regular directory.");
        }
    }

    private static void EnsureRegularFile(string path, string label)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (!file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new UpdaterConfigurationException(
                $"{label} must reference an existing regular file.");
        }
    }

    private static bool IsWithin(string root, string candidate)
    {
        var relative = Path.GetRelativePath(root, candidate);
        return relative == "." ||
            (!Path.IsPathRooted(relative) &&
             relative != ".." &&
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

    private static StringComparer PathComparer =>
        OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
}
