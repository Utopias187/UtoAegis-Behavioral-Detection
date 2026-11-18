namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableAnalyzerOptions
{
    public const long DefaultMaximumFileSizeBytes = 512L * 1024 * 1024;
    public const int DefaultMaximumSectionCount = 96;
    public const int DefaultMaximumImportCount = 8_192;
    public const int DefaultMaximumExportCount = 8_192;
    public const int DefaultMaximumResourceCount = 4_096;

    public PortableExecutableAnalyzerOptions(
        long maximumFileSizeBytes = DefaultMaximumFileSizeBytes,
        int maximumSectionCount = DefaultMaximumSectionCount,
        int maximumImportCount = DefaultMaximumImportCount,
        int maximumExportCount = DefaultMaximumExportCount,
        int maximumResourceCount = DefaultMaximumResourceCount)
    {
        if (maximumFileSizeBytes is < 64 or > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFileSizeBytes));
        }

        if (maximumSectionCount is < 1 or > 512)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumSectionCount));
        }

        if (maximumImportCount is < 1 or > 65_536)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumImportCount));
        }

        if (maximumExportCount is < 1 or > 65_536)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumExportCount));
        }

        if (maximumResourceCount is < 1 or > 65_536)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResourceCount));
        }

        MaximumFileSizeBytes = maximumFileSizeBytes;
        MaximumSectionCount = maximumSectionCount;
        MaximumImportCount = maximumImportCount;
        MaximumExportCount = maximumExportCount;
        MaximumResourceCount = maximumResourceCount;
    }

    public long MaximumFileSizeBytes { get; }

    public int MaximumSectionCount { get; }

    public int MaximumImportCount { get; }

    public int MaximumExportCount { get; }

    public int MaximumResourceCount { get; }
}
