using UtoAegis.Core.Behavior;

namespace UtoAegis.Infrastructure.Behavior;

public sealed class WindowsBehaviorDetectionPipeline : IDisposable
{
    private readonly object sync = new();
    private readonly WindowsBehaviorNormalizer normalizer;
    private readonly BoundedBehaviorEventIngestor ingestor;
    private readonly BehaviorDetectionCoordinator coordinator;

    public WindowsBehaviorDetectionPipeline(
        int queueCapacity,
        Guid? collectorGenerationId = null,
        TimeProvider? timeProvider = null)
    {
        var generation = collectorGenerationId ?? Guid.NewGuid();
        normalizer = new WindowsBehaviorNormalizer(generation);
        ingestor = new BoundedBehaviorEventIngestor(queueCapacity, generation, timeProvider);
        coordinator = new BehaviorDetectionCoordinator();
    }

    public Guid CollectorGenerationId => ingestor.CollectorGenerationId;

    public long DroppedEventCount => ingestor.DroppedEventCount;

    public IReadOnlyList<BehaviorAssessment> Process(WindowsBehaviorRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        lock (sync)
        {
            if (!normalizer.TryNormalize(record, out var draft) ||
                !ingestor.TryIngest(draft!, out _))
            {
                return [];
            }

            var assessments = new List<BehaviorAssessment>();
            while (ingestor.TryRead(out var item))
            {
                assessments.AddRange(coordinator.Accept(item!));
            }

            return assessments;
        }
    }

    public void Dispose() => ingestor.Dispose();
}
