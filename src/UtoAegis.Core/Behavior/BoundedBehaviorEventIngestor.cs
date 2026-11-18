namespace UtoAegis.Core.Behavior;

public sealed class BoundedBehaviorEventIngestor : IDisposable
{
    public const int MaximumCapacity = 8_192;

    private readonly object sync = new();
    private readonly Queue<BehaviorEvent> queue;
    private readonly SemaphoreSlim available = new(0);
    private readonly TimeProvider timeProvider;
    private long nextSequence;
    private long droppedEventCount;
    private long pendingDroppedEventCount;
    private bool disposed;

    public BoundedBehaviorEventIngestor(
        int capacity,
        Guid? collectorGenerationId = null,
        TimeProvider? timeProvider = null)
    {
        if (capacity is < 2 or > MaximumCapacity)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        var generation = collectorGenerationId ?? Guid.NewGuid();
        if (generation == Guid.Empty)
        {
            throw new ArgumentException("Collector generation IDs cannot be empty.", nameof(collectorGenerationId));
        }

        Capacity = capacity;
        CollectorGenerationId = generation;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        queue = new Queue<BehaviorEvent>(capacity);
    }

    public int Capacity { get; }

    public Guid CollectorGenerationId { get; }

    public int Count
    {
        get
        {
            lock (sync)
            {
                return queue.Count;
            }
        }
    }

    public long DroppedEventCount
    {
        get
        {
            lock (sync)
            {
                return droppedEventCount;
            }
        }
    }

    public bool TryIngest(BehaviorEventDraft draft, out BehaviorEvent? accepted)
    {
        ArgumentNullException.ThrowIfNull(draft);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            ValidateDraftGeneration(draft);
            if (queue.Count == Capacity)
            {
                droppedEventCount = checked(droppedEventCount + 1);
                pendingDroppedEventCount = checked(pendingDroppedEventCount + 1);
                accepted = null;
                return false;
            }

            accepted = CreateEvent(draft);
            queue.Enqueue(accepted);
            available.Release();
            return true;
        }
    }

    public bool TryRead(out BehaviorEvent? result)
    {
        if (!available.Wait(0))
        {
            result = null;
            return false;
        }

        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            result = DequeueAndReportGap();
            return true;
        }
    }

    public async ValueTask<BehaviorEvent> ReadAsync(CancellationToken cancellationToken = default)
    {
        await available.WaitAsync(cancellationToken).ConfigureAwait(false);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return DequeueAndReportGap();
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            queue.Clear();
        }

        available.Dispose();
    }

    private BehaviorEvent DequeueAndReportGap()
    {
        var result = queue.Dequeue();
        if (pendingDroppedEventCount > 0 && queue.Count < Capacity)
        {
            var dropped = pendingDroppedEventCount;
            pendingDroppedEventCount = 0;
            queue.Enqueue(CreateEvent(new BehaviorEventDraft(
                SourceUtc: null,
                BehaviorEventSource.Collector,
                BehaviorEventKind.ProviderHealth,
                Subject: null,
                RelatedProcess: null,
                new ProviderHealthPayload(
                    BehaviorEventSource.Collector,
                    BehaviorProviderState.Degraded,
                    dropped))));
            available.Release();
        }

        return result;
    }

    private BehaviorEvent CreateEvent(BehaviorEventDraft draft) => new(
        Guid.NewGuid(),
        CollectorGenerationId,
        checked(++nextSequence),
        timeProvider.GetUtcNow(),
        draft.SourceUtc,
        draft.Source,
        draft.Kind,
        draft.Subject,
        draft.RelatedProcess,
        draft.Payload);

    private void ValidateDraftGeneration(BehaviorEventDraft draft)
    {
        if (draft.Subject is { } subject &&
            subject.CollectorGenerationId != CollectorGenerationId ||
            draft.RelatedProcess is { } related &&
            related.CollectorGenerationId != CollectorGenerationId)
        {
            throw new ArgumentException(
                "Behavioral drafts must use process instances from this collector generation.",
                nameof(draft));
        }
    }
}
