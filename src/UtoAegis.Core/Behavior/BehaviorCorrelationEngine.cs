using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Core.Behavior;

public sealed class BehaviorCorrelationEngine
{
    public const int MaximumEventCount = 256;
    public static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(5);

    private readonly BehaviorScoringPolicy policy;
    private readonly Dictionary<string, BehaviorScoringRule> rules;

    public BehaviorCorrelationEngine(BehaviorScoringPolicy? policy = null)
    {
        this.policy = policy ?? BehaviorScoringPolicy.Default;
        rules = this.policy.Rules.ToDictionary(rule => rule.FeatureId, StringComparer.Ordinal);
    }

    public BehaviorAssessment Assess(IReadOnlyList<BehaviorEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);
        if (events.Count > MaximumEventCount || events.Any(item => item is null))
        {
            throw new ArgumentOutOfRangeException(nameof(events));
        }

        var ordered = events.OrderBy(item => item.Sequence).ToArray();
        if (ordered.Select(item => item.EventId).Distinct().Count() != ordered.Length ||
            ordered.Select(item => item.Sequence).Distinct().Count() != ordered.Length)
        {
            throw new ArgumentException("Behavior correlation events must have unique IDs and sequences.", nameof(events));
        }

        var subject = ordered.Where(item => item.Subject is not null).Select(item => item.Subject!.Value)
            .Distinct().ToArray();
        if (subject.Length > 1)
        {
            throw new ArgumentException("Behavior correlation is limited to one process instance.", nameof(events));
        }

        var end = ordered.Length == 0 ? (DateTimeOffset?)null : ordered.Max(item => item.ObservedUtc);
        var startBoundary = end - CorrelationWindow;
        var window = ordered.Where(item => startBoundary is null || item.ObservedUtc >= startBoundary).ToArray();
        var providerState = ResolveProviderState(window);
        var features = ExtractFeatures(window);
        var (score, categories, contributions) = Score(features);
        var confidence = providerState switch
        {
            BehaviorProviderState.Healthy => 100,
            BehaviorProviderState.Degraded => 70,
            _ => 0
        };
        var verdict = providerState is BehaviorProviderState.Unreliable or BehaviorProviderState.Stopped
            ? RiskVerdict.Inconclusive
            : score >= policy.DetectionThreshold
                ? providerState == BehaviorProviderState.Healthy
                    ? RiskVerdict.Malicious
                    : RiskVerdict.Review
                : score >= policy.ReviewThreshold
                    ? RiskVerdict.Review
                    : RiskVerdict.NoKnownThreat;

        return new BehaviorAssessment(
            policy.PolicyId,
            policy.PolicyVersion,
            verdict,
            score,
            confidence,
            providerState,
            subject.Length == 0 ? null : subject[0],
            window.Length == 0 ? null : window.Min(item => item.ObservedUtc),
            end,
            window.Length,
            features,
            categories,
            contributions);
    }

    private static BehaviorProviderState ResolveProviderState(IReadOnlyList<BehaviorEvent> events)
    {
        var states = events.Where(item => item.Payload is ProviderHealthPayload)
            .Select(item => ((ProviderHealthPayload)item.Payload).State)
            .ToArray();
        if (states.Contains(BehaviorProviderState.Unreliable))
        {
            return BehaviorProviderState.Unreliable;
        }

        if (states.Contains(BehaviorProviderState.Stopped))
        {
            return BehaviorProviderState.Stopped;
        }

        return states.Contains(BehaviorProviderState.Degraded)
            ? BehaviorProviderState.Degraded
            : BehaviorProviderState.Healthy;
    }

    private static BehaviorRiskFeature[] ExtractFeatures(IReadOnlyList<BehaviorEvent> events)
    {
        var persistence = events.Where(item => item.Payload is RegistryChangedPayload
            {
                Location: not BehaviorRegistryLocation.Other
            }).ToArray();
        var publicNetwork = events.Where(item => item.Payload is NetworkConnectedPayload
            {
                Direction: BehaviorNetworkDirection.Outbound,
                AddressScope: BehaviorAddressScope.Public
            }).ToArray();
        var invalidImages = events.Where(item => item.Payload is ImageLoadedPayload
            {
                SignatureState: BehaviorSignatureState.Invalid
            }).ToArray();
        var fileChanges = events.Where(item => item.Payload is FileChangedPayload).ToArray();
        var elevatedStarts = events.Where(item => item.Payload is ProcessStartedPayload
            {
                Integrity: BehaviorIntegrityClass.High or BehaviorIntegrityClass.System or BehaviorIntegrityClass.Protected
            }).ToArray();
        var features = new List<BehaviorRiskFeature>();
        Add(persistence, features, "behavior.persistence.registry-change", BehaviorFeatureCategory.Persistence,
            Scale(persistence.Length, 2));
        Add(publicNetwork, features, "behavior.network.public-outbound", BehaviorFeatureCategory.Network,
            Scale(publicNetwork.Length, 1));
        Add(invalidImages, features, "behavior.module.invalid-signature", BehaviorFeatureCategory.ModuleMemory, 100);
        if (fileChanges.Length >= 20)
        {
            Add(fileChanges, features, "behavior.files.rapid-change", BehaviorFeatureCategory.FileSystemImpact,
                Scale(fileChanges.Length, 40));
        }

        AddCombined(persistence, publicNetwork, features,
            "behavior.persistence.public-network-chain", BehaviorFeatureCategory.Persistence);
        AddCombined(invalidImages, publicNetwork, features,
            "behavior.module.public-network-chain", BehaviorFeatureCategory.ModuleMemory);
        AddCombined(elevatedStarts, persistence, features,
            "behavior.execution.elevated-persistence", BehaviorFeatureCategory.ProcessExecution);
        return features.OrderBy(item => item.Id, StringComparer.Ordinal).ToArray();
    }

    private (int Score, IReadOnlyList<BehaviorCategoryScore> Categories, IReadOnlyList<BehaviorContribution> Contributions)
        Score(IReadOnlyList<BehaviorRiskFeature> features)
    {
        var pending = features.Select(feature =>
        {
            var rule = rules[feature.Id];
            var raw = Math.Max(1, checked(((rule.Weight * feature.Strength) + 50) / 100));
            return new Pending(feature, rule, raw);
        }).ToArray();
        var categories = new List<BehaviorCategoryScore>();
        var contributions = new List<BehaviorContribution>();
        foreach (var category in Enum.GetValues<BehaviorFeatureCategory>())
        {
            var remaining = policy.CategoryCaps[category];
            var rawTotal = 0;
            foreach (var item in pending.Where(item => item.Feature.Category == category)
                         .OrderByDescending(item => item.RawPoints)
                         .ThenBy(item => item.Feature.Id, StringComparer.Ordinal))
            {
                rawTotal = checked(rawTotal + item.RawPoints);
                var applied = Math.Min(remaining, item.RawPoints);
                remaining -= applied;
                contributions.Add(new BehaviorContribution(
                    item.Feature.Id,
                    category,
                    item.Feature.Strength,
                    item.Rule.Weight,
                    item.RawPoints,
                    applied,
                    item.Rule.Explanation,
                    item.Feature.EventIds));
            }

            categories.Add(new BehaviorCategoryScore(
                category,
                rawTotal,
                policy.CategoryCaps[category],
                policy.CategoryCaps[category] - remaining));
        }

        return (
            Math.Min(100, categories.Sum(item => item.AppliedPoints)),
            categories,
            contributions.OrderBy(item => item.FeatureId, StringComparer.Ordinal).ToArray());
    }

    private static void Add(
        BehaviorEvent[] evidence,
        ICollection<BehaviorRiskFeature> features,
        string id,
        BehaviorFeatureCategory category,
        int strength)
    {
        if (evidence.Length > 0)
        {
            features.Add(new BehaviorRiskFeature(id, category, strength,
                evidence.Take(BehaviorRiskFeature.MaximumEventIdCount).Select(item => item.EventId).ToArray()));
        }
    }

    private static void AddCombined(
        BehaviorEvent[] first,
        BehaviorEvent[] second,
        ICollection<BehaviorRiskFeature> features,
        string id,
        BehaviorFeatureCategory category)
    {
        if (first.Length > 0 && second.Length > 0)
        {
            Add(first.Concat(second).DistinctBy(item => item.EventId).ToArray(), features, id, category, 100);
        }
    }

    private static int Scale(int value, int fullStrengthValue) =>
        Math.Clamp(checked((value * 100) / fullStrengthValue), 1, 100);

    private sealed record Pending(
        BehaviorRiskFeature Feature,
        BehaviorScoringRule Rule,
        int RawPoints);
}
