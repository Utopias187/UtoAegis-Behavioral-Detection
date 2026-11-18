namespace UtoAegis.Core.RiskScoring;

public sealed record RiskFeature
{
    public const int MaximumIdLength = 96;

    public RiskFeature(string id, RiskFeatureCategory category, int strength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        if (id.Length > MaximumIdLength ||
            id.Any(character =>
                character is not (>= 'a' and <= 'z') &&
                !char.IsAsciiDigit(character) &&
                character is not '.' and not '-'))
        {
            throw new ArgumentException(
                "Risk feature IDs must use bounded lowercase ASCII identifiers.",
                nameof(id));
        }

        if (!Enum.IsDefined(category))
        {
            throw new ArgumentOutOfRangeException(nameof(category));
        }

        if (strength is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(strength));
        }

        Id = id;
        Category = category;
        Strength = strength;
    }

    public string Id { get; }

    public RiskFeatureCategory Category { get; }

    public int Strength { get; }
}
