namespace UtoAegis.Core.Scanning;

/// <summary>
/// Routes each scan through one immutable scanner generation.
/// </summary>
public sealed class ReloadableFileScanner : IFileScanner
{
    private ScannerState _state;
    private long _nextGeneration = 1;

    public ReloadableFileScanner(IFileScanner initialScanner)
    {
        ArgumentNullException.ThrowIfNull(initialScanner);
        _state = new ScannerState(initialScanner, _nextGeneration);
    }

    public long Generation => Volatile.Read(ref _state).Generation;

    public long Replace(IFileScanner scanner)
    {
        ArgumentNullException.ThrowIfNull(scanner);
        var generation = Interlocked.Increment(ref _nextGeneration);
        Interlocked.Exchange(ref _state, new ScannerState(scanner, generation));
        return generation;
    }

    public ValueTask<FileScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var scanner = Volatile.Read(ref _state).Scanner;
        return scanner.ScanAsync(path, cancellationToken);
    }

    private sealed record ScannerState(IFileScanner Scanner, long Generation);
}
