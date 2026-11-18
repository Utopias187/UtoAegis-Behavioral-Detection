namespace UtoAegis.Core.RiskScoring;

public sealed class RiskScoringEngine
{
    public const int MaximumInputFeatureCount = 64;

    private readonly RiskScoringPolicy policy;
    private readonly Dictionary<string, RiskScoringRule> rules;

    public RiskScoringEngine(RiskScoringPolicy? policy = null)
    {
        this.policy = policy ?? RiskScoringPolicy.Default;
        rules = this.policy.Rules.ToDictionary(rule => rule.FeatureId, StringComparer.Ordinal);
    }

    public RiskScoreResult Score(IReadOnlyList<RiskFeature> features)
    {
        ArgumentNullException.ThrowIfNull(features);
        if (features.Count > MaximumInputFeatureCount)
        {
            throw new ArgumentOutOfRangeException(nameof(features));
        }

        var copied = features.ToArray();
        if (copied.Any(feature => feature is null) ||
            copied.Select(feature => feature.Id).Distinct(StringComparer.Ordinal).Count() != copied.Length)
        {
            throw new ArgumentException("Risk features must be non-null and unique.", nameof(features));
        }

        var pending = new List<PendingContribution>();
        var ignored = 0;
        foreach (var feature in copied)
        {
            if (!rules.TryGetValue(feature.Id, out var rule))
            {
                ignored++;
                continue;
            }

            if (feature.Category != rule.Category)
            {
                throw new ArgumentException(
                    $"Risk feature '{feature.Id}' does not match its policy category.",
                    nameof(features));
            }

            var rawPoints = Math.Max(
                1,
                checked(((rule.Weight * feature.Strength) + 50) / 100));
            pending.Add(new PendingContribution(feature, rule, rawPoints));
        }

        var contributions = new List<RiskContribution>(pending.Count);
        var categoryScores = new List<RiskCategoryScore>();
        foreach (var category in Enum.GetValues<RiskFeatureCategory>())
        {
            var categoryPending = pending
                .Where(contribution => contribution.Feature.Category == category)
                .OrderByDescending(contribution => contribution.RawPoints)
                .ThenBy(contribution => contribution.Feature.Id, StringComparer.Ordinal)
                .ToArray();
            var cap = policy.CategoryCaps[category];
            var remaining = cap;
            var rawTotal = 0;
            foreach (var contribution in categoryPending)
            {
                rawTotal = checked(rawTotal + contribution.RawPoints);
                var applied = Math.Min(remaining, contribution.RawPoints);
                remaining -= applied;
                contributions.Add(new RiskContribution(
                    contribution.Feature.Id,
                    category,
                    contribution.Feature.Strength,
                    contribution.Rule.Weight,
                    contribution.RawPoints,
                    applied,
                    contribution.Rule.Explanation));
            }

            categoryScores.Add(new RiskCategoryScore(
                category,
                rawTotal,
                cap,
                cap - remaining));
        }

        var score = Math.Min(100, categoryScores.Sum(category => category.AppliedPoints));
        return new RiskScoreResult(
            policy.PolicyId,
            policy.PolicyVersion,
            score,
            ignored,
            categoryScores,
            contributions.OrderBy(contribution => contribution.FeatureId, StringComparer.Ordinal).ToArray());
    }

    private sealed record PendingContribution(
        RiskFeature Feature,
        RiskScoringRule Rule,
        int RawPoints);
}
