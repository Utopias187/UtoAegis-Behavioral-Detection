namespace UtoAegis.Infrastructure.Telemetry;

public sealed record SecurityTelemetrySpoolOptions
{
    public const int DefaultMaximumRecords = 10_000;
    public const int MaximumAllowedRecords = 1_000_000;
    public const int DefaultMaximumRecordBytes = 16 * 1024;
    public const int MaximumAllowedRecordBytes = 64 * 1024;

    public SecurityTelemetrySpoolOptions(
        int maximumRecords = DefaultMaximumRecords,
        int maximumRecordBytes = DefaultMaximumRecordBytes)
    {
        if (maximumRecords is < 1 or > MaximumAllowedRecords)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        if (maximumRecordBytes is < 1024 or > MaximumAllowedRecordBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecordBytes));
        }

        MaximumRecords = maximumRecords;
        MaximumRecordBytes = maximumRecordBytes;
    }

    public int MaximumRecords { get; }

    public int MaximumRecordBytes { get; }
}
