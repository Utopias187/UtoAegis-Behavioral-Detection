using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service;

internal interface IServiceThreatContentSource
{
    ValueTask<ThreatContentStoreStatus> GetStatusAsync(
        CancellationToken cancellationToken = default);

    ValueTask<IServiceThreatContentLease> GetActiveAsync(
        CancellationToken cancellationToken = default);
}

internal interface IServiceThreatContentLease : IDisposable
{
    ThreatContentSnapshot Snapshot { get; }
}

internal sealed class ServiceThreatContentSource(ThreatContentStore store) :
    IServiceThreatContentSource
{
    public ValueTask<ThreatContentStoreStatus> GetStatusAsync(
        CancellationToken cancellationToken = default) =>
        store.GetStatusReadOnlyAsync(cancellationToken);

    public async ValueTask<IServiceThreatContentLease> GetActiveAsync(
        CancellationToken cancellationToken = default) =>
        new ServiceThreatContentLease(
            await store.GetActiveLeasedReadOnlyAsync(cancellationToken)
                .ConfigureAwait(false));
}

internal sealed class ServiceThreatContentLease(ThreatContentReadLease lease) :
    IServiceThreatContentLease
{
    public ThreatContentSnapshot Snapshot => lease.Snapshot;

    public void Dispose() => lease.Dispose();
}
