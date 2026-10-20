using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service;

internal sealed record ServiceDetectionSources(
    string? DatabasePath,
    string? SignaturePath,
    IServiceThreatContentSource? ManagedSource,
    ThreatContentSnapshot? ManagedSnapshot)
{
    public bool IsManagedContent => ManagedSnapshot is not null;

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
        var snapshot = await contentStore.GetActiveReadOnlyAsync(cancellationToken)
            .ConfigureAwait(false);
        return new ServiceDetectionSources(
            snapshot.ReputationDatabasePath,
            snapshot.SignatureRulesPath,
            new ServiceThreatContentSource(contentStore),
            snapshot);
    }
}
