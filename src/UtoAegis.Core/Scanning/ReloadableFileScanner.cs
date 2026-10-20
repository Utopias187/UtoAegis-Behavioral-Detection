namespace UtoAegis.Core.Scanning;

/// <summary>
/// Routes each scan through one immutable scanner generation.
/// </summary>
public sealed class ReloadableFileScanner : IFileScanner, IDisposable
{
    private ScannerState _state;
    private long _nextGeneration = 1;
    private int _disposed;

    public ReloadableFileScanner(IFileScanner initialScanner)
    {
        ArgumentNullException.ThrowIfNull(initialScanner);
        _state = new ScannerState(initialScanner, _nextGeneration);
    }

    public long Generation => Volatile.Read(ref _state).Generation;

    public long Replace(IFileScanner scanner)
    {
        ArgumentNullException.ThrowIfNull(scanner);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var generation = Interlocked.Increment(ref _nextGeneration);
        var previous = Interlocked.Exchange(
            ref _state,
            new ScannerState(scanner, generation));
        previous.Retire();
        return generation;
    }

    public async ValueTask<FileScanResult> ScanAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        while (true)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            var state = Volatile.Read(ref _state);
            if (!state.TryAcquire())
            {
                continue;
            }

            try
            {
                return await state.Scanner.ScanAsync(path, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                state.Release();
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Volatile.Read(ref _state).Retire();
        }
    }

    private sealed class ScannerState(IFileScanner scanner, long generation)
    {
        private readonly Lock _gate = new();
        private int _activeScans;
        private bool _retired;
        private bool _scannerDisposed;

        public IFileScanner Scanner { get; } = scanner;

        public long Generation { get; } = generation;

        public bool TryAcquire()
        {
            lock (_gate)
            {
                if (_retired)
                {
                    return false;
                }

                _activeScans++;
                return true;
            }
        }

        public void Release()
        {
            bool shouldDispose;
            lock (_gate)
            {
                _activeScans--;
                shouldDispose = _retired && _activeScans == 0 && !_scannerDisposed;
                _scannerDisposed |= shouldDispose;
            }

            if (shouldDispose)
            {
                DisposeScanner();
            }
        }

        public void Retire()
        {
            bool shouldDispose;
            lock (_gate)
            {
                _retired = true;
                shouldDispose = _activeScans == 0 && !_scannerDisposed;
                _scannerDisposed |= shouldDispose;
            }

            if (shouldDispose)
            {
                DisposeScanner();
            }
        }

        private void DisposeScanner()
        {
            try
            {
                (Scanner as IDisposable)?.Dispose();
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}
