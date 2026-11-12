using UtoAegis.Infrastructure.Telemetry;

namespace UtoAegis.Telemetry;

public sealed class TelemetryForwarderEngine(
    TelemetryConfiguration configuration,
    TelemetryCollectorClient collectorClient)
{
    public async ValueTask<IReadOnlyList<TelemetrySourceDeliveryResult>> RunOnceAsync(
        CancellationToken cancellationToken = default)
    {
        var results = new List<TelemetrySourceDeliveryResult>(configuration.Sources.Count);
        foreach (var source in configuration.Sources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var checkpointStore = new SecurityTelemetryCheckpointStore(
                Path.Combine(configuration.StatePath, $"{source.Name}.checkpoint.json"));
            var checkpoint = await checkpointStore.LoadAsync(cancellationToken)
                .ConfigureAwait(false);
            using var spool = new SecurityTelemetrySpool(
                source.SpoolPath,
                new SecurityTelemetrySpoolOptions(
                    SecurityTelemetrySpoolOptions.MaximumAllowedRecords));
            var records = await spool.ReadBatchAsync(
                checkpoint,
                configuration.BatchSize,
                cancellationToken).ConfigureAwait(false);
            if (records.Count == 0)
            {
                results.Add(new TelemetrySourceDeliveryResult(
                    source.Name,
                    0,
                    checkpoint.Sequence));
                continue;
            }

            var expected = records[^1];
            var acknowledgement = await collectorClient.SendAsync(
                source.Name,
                records,
                cancellationToken).ConfigureAwait(false);
            if (acknowledgement.AcceptedSequence != expected.Sequence ||
                !string.Equals(
                    acknowledgement.AcceptedHash,
                    expected.Hash,
                    StringComparison.Ordinal))
            {
                throw new TelemetryCollectorException(
                    "The collector acknowledgement does not match the final record in the submitted batch.");
            }

            await checkpointStore.SaveAsync(
                new SecurityTelemetryCheckpoint(
                    acknowledgement.AcceptedSequence,
                    acknowledgement.AcceptedHash),
                cancellationToken).ConfigureAwait(false);
            results.Add(new TelemetrySourceDeliveryResult(
                source.Name,
                records.Count,
                acknowledgement.AcceptedSequence));
        }

        return results;
    }
}
