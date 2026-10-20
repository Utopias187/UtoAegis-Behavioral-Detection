using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service;

internal interface IServiceThreatContentSource
{
    ValueTask<ThreatContentStoreStatus> GetStatusAsync(
        CancellationToken cancellationToken = default);

    ValueTask<ThreatContentSnapshot> GetActiveAsync(
        CancellationToken cancellationToken = default);
}

internal sealed class ServiceThreatContentSource(ThreatContentStore store) :
    IServiceThreatContentSource
{
    public ValueTask<ThreatContentStoreStatus> GetStatusAsync(
        CancellationToken cancellationToken = default) =>
        store.GetStatusAsync(cancellationToken);

    public ValueTask<ThreatContentSnapshot> GetActiveAsync(
        CancellationToken cancellationToken = default) =>
        store.GetActiveReadOnlyAsync(cancellationToken);
}
