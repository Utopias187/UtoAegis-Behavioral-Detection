namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableAnalyzerOptions
{
    public const long DefaultMaximumFileSizeBytes = 512L * 1024 * 1024;
    public const int DefaultMaximumSectionCount = 96;
    public const int DefaultMaximumImportCount = 8_192;
    public const int DefaultMaximumExportCount = 8_192;
    public const int DefaultMaximumResourceCount = 4_096;
    public const int DefaultMaximumDebugEntryCount = 128;
    public const int DefaultMaximumTlsCallbackCount = 256;
    public const int DefaultMaximumRelocationCount = 131_072;
    public const int DefaultMaximumExceptionEntryCount = 65_536;

    public PortableExecutableAnalyzerOptions(
        long maximumFileSizeBytes = DefaultMaximumFileSizeBytes,
        int maximumSectionCount = DefaultMaximumSectionCount,
        int maximumImportCount = DefaultMaximumImportCount,
        int maximumExportCount = DefaultMaximumExportCount,
        int maximumResourceCount = DefaultMaximumResourceCount,
        int maximumDebugEntryCount = DefaultMaximumDebugEntryCount,
        int maximumTlsCallbackCount = DefaultMaximumTlsCallbackCount,
        int maximumRelocationCount = DefaultMaximumRelocationCount,
        int maximumExceptionEntryCount = DefaultMaximumExceptionEntryCount)
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

        if (maximumDebugEntryCount is < 1 or > 4_096)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDebugEntryCount));
        }

        if (maximumTlsCallbackCount is < 1 or > 4_096)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumTlsCallbackCount));
        }

        if (maximumRelocationCount is < 1 or > 1_048_576)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRelocationCount));
        }

        if (maximumExceptionEntryCount is < 1 or > 1_048_576)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumExceptionEntryCount));
        }

        MaximumFileSizeBytes = maximumFileSizeBytes;
        MaximumSectionCount = maximumSectionCount;
        MaximumImportCount = maximumImportCount;
        MaximumExportCount = maximumExportCount;
        MaximumResourceCount = maximumResourceCount;
        MaximumDebugEntryCount = maximumDebugEntryCount;
        MaximumTlsCallbackCount = maximumTlsCallbackCount;
        MaximumRelocationCount = maximumRelocationCount;
        MaximumExceptionEntryCount = maximumExceptionEntryCount;
    }

    public long MaximumFileSizeBytes { get; }

    public int MaximumSectionCount { get; }

    public int MaximumImportCount { get; }

    public int MaximumExportCount { get; }

    public int MaximumResourceCount { get; }

    public int MaximumDebugEntryCount { get; }

    public int MaximumTlsCallbackCount { get; }

    public int MaximumRelocationCount { get; }

    public int MaximumExceptionEntryCount { get; }
}
