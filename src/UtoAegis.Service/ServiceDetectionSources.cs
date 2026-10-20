using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service;

internal sealed record ServiceDetectionSources(
    string? DatabasePath,
    string? SignaturePath,
    IServiceThreatContentSource? ManagedSource,
    IServiceThreatContentLease? ManagedContent) : IDisposable
{
    public bool IsManagedContent => ManagedContent is not null;

    public ThreatContentSnapshot? ManagedSnapshot => ManagedContent?.Snapshot;

    public string? ContentVersion => ManagedSnapshot?.Manifest.Version;

    public long? ContentSequence => ManagedSnapshot?.Manifest.Sequence;

    public string? SigningKeyId => ManagedSnapshot?.Manifest.KeyId;

    public DateTimeOffset? ExpiresUtc => ManagedSnapshot?.Manifest.ExpiresUtc;

    public static async ValueTask<ServiceDetectionSources> ResolveAsync(
        ServiceConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (configuration.ContentStorePath is null)
        {
            return new ServiceDetectionSources(
                configuration.DatabasePath,
                configuration.SignaturePath,
                null,
                null);
        }

        var trustStore = await ThreatTrustStoreFileLoader.LoadAsync(
            configuration.TrustedSigningKeyPaths,
            cancellationToken).ConfigureAwait(false);
        var verifier = new SignedThreatBundleVerifier(trustStore);
        var contentStore = new ThreatContentStore(configuration.ContentStorePath, verifier);
        var source = new ServiceThreatContentSource(contentStore);
        var content = await source.GetActiveAsync(cancellationToken).ConfigureAwait(false);
        return new ServiceDetectionSources(
            content.Snapshot.ReputationDatabasePath,
            content.Snapshot.SignatureRulesPath,
            source,
            content);
    }

    public void Dispose() => ManagedContent?.Dispose();
}
