using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace UtoAegis.Telemetry;

public sealed class TelemetryConfiguration
{
    public static readonly TimeSpan MinimumPollInterval = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan MaximumPollInterval = TimeSpan.FromHours(1);
    public static readonly TimeSpan MinimumRequestTimeout = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan MaximumRequestTimeout = TimeSpan.FromMinutes(2);

    private TelemetryConfiguration(
        Uri collectorUri,
        string authenticationKeyId,
        string authenticationKeyPath,
        string statePath,
        IReadOnlyList<TelemetrySourceConfiguration> sources,
        int batchSize,
        TimeSpan pollInterval,
        TimeSpan requestTimeout)
    {
        CollectorUri = collectorUri;
        AuthenticationKeyId = authenticationKeyId;
        AuthenticationKeyPath = authenticationKeyPath;
        StatePath = statePath;
        Sources = sources;
        BatchSize = batchSize;
        PollInterval = pollInterval;
        RequestTimeout = requestTimeout;
    }

    public Uri CollectorUri { get; }

    public string AuthenticationKeyId { get; }

    public string AuthenticationKeyPath { get; }

    public string StatePath { get; }

    public IReadOnlyList<TelemetrySourceConfiguration> Sources { get; }

    public int BatchSize { get; }

    public TimeSpan PollInterval { get; }

    public TimeSpan RequestTimeout { get; }

    public static TelemetryConfiguration Load(
        IConfiguration configuration,
        string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        var section = configuration.GetSection("UtoAegisTelemetry");
        try
        {
            var collectorText = section["CollectorUri"]?.Trim();
            if (!Uri.TryCreate(collectorText, UriKind.Absolute, out var collectorUri) ||
                !string.Equals(collectorUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrEmpty(collectorUri.UserInfo) ||
                !string.IsNullOrEmpty(collectorUri.Fragment))
            {
                throw new TelemetryConfigurationException(
                    "UtoAegisTelemetry:CollectorUri must be an absolute HTTPS URI without user information or a fragment.");
            }

            var resolvedBase = Path.GetFullPath(baseDirectory);
            var keyId = RequiredIdentifier(section, "AuthenticationKeyId");
            var keyPath = RequiredPath(section, "AuthenticationKeyPath", resolvedBase);
            EnsureRegularFile(keyPath, "AuthenticationKeyPath");
            var statePath = RequiredPath(section, "StatePath", resolvedBase);
            EnsureRegularDirectory(statePath, "StatePath");
            var sources = new List<TelemetrySourceConfiguration>();
            var sourceNames = new HashSet<string>(StringComparer.Ordinal);
            var sourcePaths = new HashSet<string>(PathComparer);
            foreach (var child in section.GetSection("Sources").GetChildren())
            {
                var name = RequiredIdentifier(child, "Name");
                var spoolPath = RequiredPath(child, "SpoolPath", resolvedBase);
                EnsureRegularDirectory(spoolPath, $"source '{name}' spool");
                if (!sourceNames.Add(name) || !sourcePaths.Add(spoolPath))
                {
                    throw new TelemetryConfigurationException(
                        "Telemetry source names and spool paths must be unique.");
                }

                sources.Add(new TelemetrySourceConfiguration(name, spoolPath));
                if (sources.Count > 32)
                {
                    throw new TelemetryConfigurationException(
                        "At most 32 telemetry sources may be configured.");
                }
            }

            if (sources.Count == 0)
            {
                throw new TelemetryConfigurationException(
                    "At least one telemetry source must be configured.");
            }

            var installationPath = Path.GetFullPath(resolvedBase);
            if (PathEquals(statePath, Path.GetPathRoot(statePath)!) ||
                IsWithin(statePath, installationPath) ||
                IsWithin(installationPath, statePath))
            {
                throw new TelemetryConfigurationException(
                    "Telemetry state must be outside the installation directory and not a filesystem root.");
            }

            if (sources.Any(source =>
                    PathEquals(source.SpoolPath, statePath) ||
                    IsWithin(source.SpoolPath, statePath) ||
                    IsWithin(statePath, source.SpoolPath)))
            {
                throw new TelemetryConfigurationException(
                    "Telemetry source spools and forwarder state must be distinct and non-nested.");
            }

            if (IsWithin(statePath, keyPath) ||
                sources.Any(source => IsWithin(source.SpoolPath, keyPath)))
            {
                throw new TelemetryConfigurationException(
                    "The collector authentication key must be outside telemetry state and source spools.");
            }

            var batchSize = ReadInt(section, "BatchSize", 128);
            if (batchSize is < 1 or > 1000)
            {
                throw new TelemetryConfigurationException(
                    "BatchSize must be from 1 through 1000.");
            }

            var pollInterval = TimeSpan.FromSeconds(ReadInt(section, "PollIntervalSeconds", 30));
            if (pollInterval < MinimumPollInterval || pollInterval > MaximumPollInterval)
            {
                throw new TelemetryConfigurationException(
                    "PollIntervalSeconds must be from 5 through 3600.");
            }

            var requestTimeout = TimeSpan.FromSeconds(ReadInt(section, "RequestTimeoutSeconds", 30));
            if (requestTimeout < MinimumRequestTimeout || requestTimeout > MaximumRequestTimeout)
            {
                throw new TelemetryConfigurationException(
                    "RequestTimeoutSeconds must be from 5 through 120.");
            }

            return new TelemetryConfiguration(
                collectorUri,
                keyId,
                keyPath,
                statePath,
                sources,
                batchSize,
                pollInterval,
                requestTimeout);
        }
        catch (TelemetryConfigurationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException or
                NotSupportedException or PathTooLongException or OverflowException)
        {
            throw new TelemetryConfigurationException(
                "The UtoAegis telemetry configuration is invalid.",
                exception);
        }
    }

    public static byte[] LoadAuthenticationKey(string path)
    {
        try
        {
            var text = File.ReadAllText(path).Trim();
            var key = Convert.FromBase64String(text);
            if (key.Length is < 32 or > 64)
            {
                throw new TelemetryConfigurationException(
                    "The collector authentication key must decode to 32 through 64 bytes.");
            }

            return key;
        }
        catch (FormatException exception)
        {
            throw new TelemetryConfigurationException(
                "The collector authentication key must contain base64 text.",
                exception);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            throw new TelemetryConfigurationException(
                "The collector authentication key could not be read.",
                exception);
        }
    }

    private static string RequiredIdentifier(IConfiguration section, string key)
    {
        var value = section[key]?.Trim();
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 64 ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            !char.IsAsciiLetterOrDigit(value[^1]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_'))
        {
            throw new TelemetryConfigurationException(
                $"UtoAegisTelemetry:{key} must use 1 to 64 path-safe ASCII characters.");
        }

        return value;
    }

    private static string RequiredPath(
        IConfiguration section,
        string key,
        string baseDirectory)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new TelemetryConfigurationException($"UtoAegisTelemetry:{key} is required.");
        }

        return Path.GetFullPath(Environment.ExpandEnvironmentVariables(value.Trim()), baseDirectory);
    }

    private static int ReadInt(IConfiguration section, string key, int defaultValue)
    {
        var text = section[key];
        if (string.IsNullOrWhiteSpace(text))
        {
            return defaultValue;
        }

        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            throw new TelemetryConfigurationException(
                $"UtoAegisTelemetry:{key} must be an integer.");
        }

        return value;
    }

    private static void EnsureRegularDirectory(string path, string label)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new TelemetryConfigurationException(
                $"{label} must reference an existing regular directory.");
        }
    }

    private static void EnsureRegularFile(string path, string label)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (!file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new TelemetryConfigurationException(
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
