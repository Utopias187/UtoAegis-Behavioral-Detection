namespace UtoAegis.Core.Behavior;

public enum BehaviorFeatureCategory
{
    ProcessExecution = 0,
    ModuleMemory = 1,
    Persistence = 2,
    DefenseEvasion = 3,
    FileSystemImpact = 4,
    Network = 5
}

public sealed record BehaviorRiskFeature
{
    public const int MaximumEventIdCount = 64;

    public BehaviorRiskFeature(
        string id,
        BehaviorFeatureCategory category,
        int strength,
        IReadOnlyCollection<Guid> eventIds)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        if (id.Length > 96 || !id.StartsWith("behavior.", StringComparison.Ordinal) ||
            id.Any(character =>
                character is not (>= 'a' and <= 'z') &&
                !char.IsAsciiDigit(character) &&
                character is not '.' and not '-'))
        {
            throw new ArgumentException("Behavior feature IDs must be bounded lowercase identifiers.", nameof(id));
        }

        if (!Enum.IsDefined(category))
        {
            throw new ArgumentOutOfRangeException(nameof(category));
        }

        if (strength is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(strength));
        }

        ArgumentNullException.ThrowIfNull(eventIds);
        var copiedIds = eventIds.Distinct().Order().ToArray();
        if (copiedIds.Length is < 1 or > MaximumEventIdCount || copiedIds.Any(id => id == Guid.Empty))
        {
            throw new ArgumentOutOfRangeException(nameof(eventIds));
        }

        Id = id;
        Category = category;
        Strength = strength;
        EventIds = copiedIds;
    }

    public string Id { get; }

    public BehaviorFeatureCategory Category { get; }

    public int Strength { get; }

    public IReadOnlyList<Guid> EventIds { get; }
}
