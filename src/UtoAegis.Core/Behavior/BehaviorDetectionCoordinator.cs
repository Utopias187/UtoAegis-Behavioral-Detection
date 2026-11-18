namespace UtoAegis.Core.Behavior;

public sealed class BehaviorDetectionCoordinator
{
    public const int MaximumActiveProcessCount = 4_096;
    public const int MaximumHealthEventCount = 64;

    private readonly BehaviorCorrelationEngine engine;
    private readonly Dictionary<BehaviorProcessInstance, ProcessWindow> windows = [];
    private readonly List<BehaviorEvent> healthEvents = [];
    private Guid? collectorGenerationId;
    private long lastSequence;

    public BehaviorDetectionCoordinator(BehaviorCorrelationEngine? engine = null)
    {
        this.engine = engine ?? new BehaviorCorrelationEngine();
    }

    public int ActiveProcessCount => windows.Count;

    public IReadOnlyList<BehaviorAssessment> Accept(BehaviorEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (collectorGenerationId is null)
        {
            collectorGenerationId = item.CollectorGenerationId;
        }
        else if (collectorGenerationId != item.CollectorGenerationId)
        {
            throw new ArgumentException("A coordinator cannot correlate across collector generations.", nameof(item));
        }

        if (item.Sequence <= lastSequence)
        {
            throw new ArgumentException("Behavior events must arrive in increasing receipt order.", nameof(item));
        }

        lastSequence = item.Sequence;
        if (item.Kind == BehaviorEventKind.ProviderHealth)
        {
            healthEvents.Add(item);
            TrimHealth(item.ObservedUtc);
            return windows.Values
                .OrderBy(window => window.LastSequence)
                .Select(window => engine.Assess(window.Events.Concat(healthEvents).ToArray()))
                .ToArray();
        }

        var subject = item.Subject!.Value;
        if (!windows.TryGetValue(subject, out var processWindow))
        {
            if (windows.Count == MaximumActiveProcessCount)
            {
                var oldest = windows.MinBy(pair => pair.Value.LastSequence).Key;
                windows.Remove(oldest);
            }

            processWindow = new ProcessWindow();
            windows.Add(subject, processWindow);
        }

        processWindow.Events.Add(item);
        processWindow.LastSequence = item.Sequence;
        var cutoff = item.ObservedUtc - BehaviorCorrelationEngine.CorrelationWindow;
        processWindow.Events.RemoveAll(existing => existing.ObservedUtc < cutoff);
        if (processWindow.Events.Count > BehaviorCorrelationEngine.MaximumEventCount - healthEvents.Count)
        {
            processWindow.Events.RemoveRange(
                0,
                processWindow.Events.Count -
                (BehaviorCorrelationEngine.MaximumEventCount - healthEvents.Count));
        }

        TrimHealth(item.ObservedUtc);
        var assessment = engine.Assess(processWindow.Events.Concat(healthEvents).ToArray());
        if (item.Kind == BehaviorEventKind.ProcessStopped)
        {
            windows.Remove(subject);
        }

        return [assessment];
    }

    private void TrimHealth(DateTimeOffset observedUtc)
    {
        var cutoff = observedUtc - BehaviorCorrelationEngine.CorrelationWindow;
        healthEvents.RemoveAll(item => item.ObservedUtc < cutoff);
        if (healthEvents.Count > MaximumHealthEventCount)
        {
            healthEvents.RemoveRange(0, healthEvents.Count - MaximumHealthEventCount);
        }
    }

    private sealed class ProcessWindow
    {
        public List<BehaviorEvent> Events { get; } = [];

        public long LastSequence { get; set; }
    }
}
