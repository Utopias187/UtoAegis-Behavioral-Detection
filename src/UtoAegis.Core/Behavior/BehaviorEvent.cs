namespace UtoAegis.Core.Behavior;

public sealed record BehaviorEvent
{
    public const int CurrentSchemaVersion = 1;

    public BehaviorEvent(
        Guid eventId,
        Guid collectorGenerationId,
        long sequence,
        DateTimeOffset observedUtc,
        DateTimeOffset? sourceUtc,
        BehaviorEventSource source,
        BehaviorEventKind kind,
        BehaviorProcessInstance? subject,
        BehaviorProcessInstance? relatedProcess,
        BehaviorEventPayload payload,
        int schemaVersion = CurrentSchemaVersion)
    {
        if (eventId == Guid.Empty || collectorGenerationId == Guid.Empty)
        {
            throw new ArgumentException("Event and collector generation IDs cannot be empty.");
        }

        ArgumentOutOfRangeException.ThrowIfNotEqual(schemaVersion, CurrentSchemaVersion);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        ArgumentNullException.ThrowIfNull(payload);
        if (!Enum.IsDefined(source) || !Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        ValidatePayload(kind, payload);
        if (kind != BehaviorEventKind.ProviderHealth && subject is null)
        {
            throw new ArgumentException("Non-health behavioral events require a process subject.", nameof(subject));
        }

        if (subject is { } subjectProcess &&
            subjectProcess.CollectorGenerationId != collectorGenerationId ||
            relatedProcess is { } related && related.CollectorGenerationId != collectorGenerationId)
        {
            throw new ArgumentException("Process instances must belong to the event collector generation.");
        }

        SchemaVersion = schemaVersion;
        EventId = eventId;
        CollectorGenerationId = collectorGenerationId;
        Sequence = sequence;
        ObservedUtc = observedUtc.ToUniversalTime();
        SourceUtc = sourceUtc?.ToUniversalTime();
        Source = source;
        Kind = kind;
        Subject = subject;
        RelatedProcess = relatedProcess;
        Payload = payload;
    }

    public int SchemaVersion { get; }

    public Guid EventId { get; }

    public Guid CollectorGenerationId { get; }

    public long Sequence { get; }

    public DateTimeOffset ObservedUtc { get; }

    public DateTimeOffset? SourceUtc { get; }

    public BehaviorEventSource Source { get; }

    public BehaviorEventKind Kind { get; }

    public BehaviorProcessInstance? Subject { get; }

    public BehaviorProcessInstance? RelatedProcess { get; }

    public BehaviorEventPayload Payload { get; }

    private static void ValidatePayload(BehaviorEventKind kind, BehaviorEventPayload payload)
    {
        var valid = kind switch
        {
            BehaviorEventKind.ProcessStarted => payload is ProcessStartedPayload
            {
                Executable: not null
            } started && Enum.IsDefined(started.Integrity),
            BehaviorEventKind.ProcessStopped => payload is ProcessStoppedPayload,
            BehaviorEventKind.ImageLoaded => payload is ImageLoadedPayload
            {
                Image: not null
            } image && Enum.IsDefined(image.SignatureState),
            BehaviorEventKind.FileChanged => payload is FileChangedPayload file &&
                Enum.IsDefined(file.Operation),
            BehaviorEventKind.RegistryChanged => payload is RegistryChangedPayload registry &&
                Enum.IsDefined(registry.Location) && Enum.IsDefined(registry.Operation),
            BehaviorEventKind.NetworkConnected => payload is NetworkConnectedPayload network &&
                Enum.IsDefined(network.Protocol) &&
                Enum.IsDefined(network.Direction) &&
                Enum.IsDefined(network.AddressScope),
            BehaviorEventKind.ProviderHealth => payload is ProviderHealthPayload health &&
                Enum.IsDefined(health.Provider) && Enum.IsDefined(health.State),
            _ => false
        };
        if (!valid)
        {
            throw new ArgumentException("The behavioral payload does not match the event kind.", nameof(payload));
        }
    }
}

public sealed record BehaviorEventDraft(
    DateTimeOffset? SourceUtc,
    BehaviorEventSource Source,
    BehaviorEventKind Kind,
    BehaviorProcessInstance? Subject,
    BehaviorProcessInstance? RelatedProcess,
    BehaviorEventPayload Payload);
