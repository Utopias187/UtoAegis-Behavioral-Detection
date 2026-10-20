namespace UtoAegis.Infrastructure.ThreatIntelligence;

public interface IRemoteThreatBundleDownloader
{
    ValueTask<DownloadedThreatBundle> DownloadAsync(
        Uri channelBaseUri,
        string downloadRoot,
        long highestAcceptedSequence,
        CancellationToken cancellationToken = default);
}
