namespace UtoAegis.Core.Behavior;

public readonly record struct BehaviorProcessInstance
{
    public BehaviorProcessInstance(Guid collectorGenerationId, int processId, long startSequence)
    {
        if (collectorGenerationId == Guid.Empty)
        {
            throw new ArgumentException("Collector generation IDs cannot be empty.", nameof(collectorGenerationId));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(processId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(startSequence);
        CollectorGenerationId = collectorGenerationId;
        ProcessId = processId;
        StartSequence = startSequence;
    }

    public Guid CollectorGenerationId { get; }

    public int ProcessId { get; }

    public long StartSequence { get; }
}
