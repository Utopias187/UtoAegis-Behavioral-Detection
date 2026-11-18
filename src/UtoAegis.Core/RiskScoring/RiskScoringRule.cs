namespace UtoAegis.Core.RiskScoring;

public sealed record RiskScoringRule
{
    public const int MaximumExplanationLength = 256;

    public RiskScoringRule(
        string featureId,
        RiskFeatureCategory category,
        int weight,
        string explanation)
    {
        _ = new RiskFeature(featureId, category, 1);
        if (weight is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(weight));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(explanation);
        if (explanation.Length > MaximumExplanationLength || explanation.Any(char.IsControl))
        {
            throw new ArgumentException(
                "Risk explanations must be bounded printable text.",
                nameof(explanation));
        }

        FeatureId = featureId;
        Category = category;
        Weight = weight;
        Explanation = explanation;
    }

    public string FeatureId { get; }

    public RiskFeatureCategory Category { get; }

    public int Weight { get; }

    public string Explanation { get; }
}
