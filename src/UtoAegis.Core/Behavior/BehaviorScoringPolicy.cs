namespace UtoAegis.Core.Behavior;

public sealed record BehaviorScoringRule
{
    public BehaviorScoringRule(
        string featureId,
        BehaviorFeatureCategory category,
        int weight,
        string explanation)
    {
        _ = new BehaviorRiskFeature(featureId, category, 1, [Guid.Parse("c77ec0df-f2b9-47ed-8140-35ae5701758d")]);
        if (weight is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(weight));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(explanation);
        if (explanation.Length > 256 || explanation.Any(char.IsControl))
        {
            throw new ArgumentException("Behavior explanations must be bounded trusted text.", nameof(explanation));
        }

        FeatureId = featureId;
        Category = category;
        Weight = weight;
        Explanation = explanation;
    }

    public string FeatureId { get; }

    public BehaviorFeatureCategory Category { get; }

    public int Weight { get; }

    public string Explanation { get; }
}

public sealed class BehaviorScoringPolicy
{
    private static readonly IReadOnlyList<BehaviorScoringRule> DefaultRules =
    [
        Rule("behavior.module.invalid-signature", BehaviorFeatureCategory.ModuleMemory, 15,
            "A loaded image reported an invalid signature state."),
        Rule("behavior.persistence.registry-change", BehaviorFeatureCategory.Persistence, 15,
            "The process modified a registry location associated with persistence."),
        Rule("behavior.network.public-outbound", BehaviorFeatureCategory.Network, 8,
            "The process established outbound connections to public address space."),
        Rule("behavior.files.rapid-change", BehaviorFeatureCategory.FileSystemImpact, 20,
            "The process changed many files within the correlation window."),
        Rule("behavior.persistence.public-network-chain", BehaviorFeatureCategory.Persistence, 25,
            "Persistence-related registry activity and public network activity occurred in one process window."),
        Rule("behavior.module.public-network-chain", BehaviorFeatureCategory.ModuleMemory, 25,
            "An invalidly signed image load and public network activity occurred in one process window."),
        Rule("behavior.execution.elevated-persistence", BehaviorFeatureCategory.ProcessExecution, 20,
            "An elevated process modified a persistence-related registry location.")
    ];

    private static readonly IReadOnlyDictionary<BehaviorFeatureCategory, int> DefaultCaps =
        new Dictionary<BehaviorFeatureCategory, int>
        {
            [BehaviorFeatureCategory.ProcessExecution] = 20,
            [BehaviorFeatureCategory.ModuleMemory] = 25,
            [BehaviorFeatureCategory.Persistence] = 30,
            [BehaviorFeatureCategory.DefenseEvasion] = 20,
            [BehaviorFeatureCategory.FileSystemImpact] = 25,
            [BehaviorFeatureCategory.Network] = 15
        };

    public static BehaviorScoringPolicy Default { get; } = new(
        "utoaegis.behavior.default",
        1,
        reviewThreshold: 35,
        detectionThreshold: 85,
        DefaultRules,
        DefaultCaps);

    public BehaviorScoringPolicy(
        string policyId,
        int policyVersion,
        int reviewThreshold,
        int detectionThreshold,
        IReadOnlyList<BehaviorScoringRule> rules,
        IReadOnlyDictionary<BehaviorFeatureCategory, int> categoryCaps)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyId);
        if (policyId.Length > 64 || policyId.Any(character =>
                character is not (>= 'a' and <= 'z') &&
                !char.IsAsciiDigit(character) &&
                character is not '.' and not '-'))
        {
            throw new ArgumentException("Behavior policy IDs must be bounded lowercase identifiers.", nameof(policyId));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(policyVersion);
        if (reviewThreshold is < 1 or > 99 || detectionThreshold is < 2 or > 100 ||
            reviewThreshold >= detectionThreshold)
        {
            throw new ArgumentException("Behavior thresholds must be increasing within 1 through 100.");
        }

        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(categoryCaps);
        var copiedRules = rules.ToArray();
        if (copiedRules.Length is < 1 or > 64 || copiedRules.Any(rule => rule is null) ||
            copiedRules.Select(rule => rule.FeatureId).Distinct(StringComparer.Ordinal).Count() != copiedRules.Length)
        {
            throw new ArgumentException("Behavior policies require 1 to 64 unique non-null rules.", nameof(rules));
        }

        var copiedCaps = new Dictionary<BehaviorFeatureCategory, int>();
        foreach (var category in Enum.GetValues<BehaviorFeatureCategory>())
        {
            if (!categoryCaps.TryGetValue(category, out var cap) || cap is < 1 or > 100)
            {
                throw new ArgumentException("Behavior policies require a cap for every category.", nameof(categoryCaps));
            }

            copiedCaps.Add(category, cap);
        }

        if (copiedCaps.Count != categoryCaps.Count)
        {
            throw new ArgumentException("Behavior policies cannot contain unknown categories.", nameof(categoryCaps));
        }

        PolicyId = policyId;
        PolicyVersion = policyVersion;
        ReviewThreshold = reviewThreshold;
        DetectionThreshold = detectionThreshold;
        Rules = copiedRules;
        CategoryCaps = copiedCaps;
    }

    public string PolicyId { get; }

    public int PolicyVersion { get; }

    public int ReviewThreshold { get; }

    public int DetectionThreshold { get; }

    public IReadOnlyList<BehaviorScoringRule> Rules { get; }

    public IReadOnlyDictionary<BehaviorFeatureCategory, int> CategoryCaps { get; }

    private static BehaviorScoringRule Rule(
        string id,
        BehaviorFeatureCategory category,
        int weight,
        string explanation) => new(id, category, weight, explanation);
}
