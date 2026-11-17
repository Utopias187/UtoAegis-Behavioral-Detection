namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableAnalyzerOptions
{
    public const long DefaultMaximumFileSizeBytes = 512L * 1024 * 1024;
    public const int DefaultMaximumSectionCount = 96;

    public PortableExecutableAnalyzerOptions(
        long maximumFileSizeBytes = DefaultMaximumFileSizeBytes,
        int maximumSectionCount = DefaultMaximumSectionCount)
    {
        if (maximumFileSizeBytes is < 64 or > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFileSizeBytes));
        }

        if (maximumSectionCount is < 1 or > 512)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumSectionCount));
        }

        MaximumFileSizeBytes = maximumFileSizeBytes;
        MaximumSectionCount = maximumSectionCount;
    }

    public long MaximumFileSizeBytes { get; }

    public int MaximumSectionCount { get; }
}
