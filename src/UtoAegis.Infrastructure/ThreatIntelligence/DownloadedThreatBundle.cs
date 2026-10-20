namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class DownloadedThreatBundle : IDisposable
{
    private readonly string _downloadRoot;
    private bool _disposed;

    internal DownloadedThreatBundle(
        string downloadRoot,
        string bundleDirectory,
        Core.ThreatIntelligence.ThreatUpdateManifest manifest)
    {
        _downloadRoot = downloadRoot;
        BundleDirectory = bundleDirectory;
        Manifest = manifest;
    }

    public string BundleDirectory { get; }

    public Core.ThreatIntelligence.ThreatUpdateManifest Manifest { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        var parent = Path.GetDirectoryName(BundleDirectory);
        if (!string.Equals(parent, _downloadRoot, PathComparison))
        {
            return;
        }

        try
        {
            if (Directory.Exists(BundleDirectory))
            {
                Directory.Delete(BundleDirectory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
}
