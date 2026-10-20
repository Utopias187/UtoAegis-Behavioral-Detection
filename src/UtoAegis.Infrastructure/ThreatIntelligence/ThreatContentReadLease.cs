namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class ThreatContentReadLease : IDisposable
{
    private readonly FileStream _databaseHandle;

    internal ThreatContentReadLease(
        ThreatContentSnapshot snapshot,
        FileStream databaseHandle)
    {
        Snapshot = snapshot;
        _databaseHandle = databaseHandle;
    }

    public ThreatContentSnapshot Snapshot { get; }

    public void Dispose() => _databaseHandle.Dispose();
}
