namespace UtoAegis.Core.RiskScoring;

public sealed class RiskScoringPolicy
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumRuleCount = 64;
    public const int MaximumPolicyIdLength = 64;

    private static readonly IReadOnlyDictionary<RiskFeatureCategory, int> DefaultCategoryCaps =
        new Dictionary<RiskFeatureCategory, int>
        {
            [RiskFeatureCategory.Structure] = 25,
            [RiskFeatureCategory.Memory] = 30,
            [RiskFeatureCategory.Packing] = 25,
            [RiskFeatureCategory.Execution] = 25,
            [RiskFeatureCategory.Network] = 15,
            [RiskFeatureCategory.Persistence] = 15,
            [RiskFeatureCategory.Hardening] = 8
        };

    private static readonly IReadOnlyList<RiskScoringRule> DefaultRules =
    [
        Rule("pe.analysis.malformed", RiskFeatureCategory.Structure, 15,
            "The PE structure is malformed and could not be analyzed completely."),
        Rule("pe.entrypoint.unmapped", RiskFeatureCategory.Structure, 25,
            "The entry point is not contained by a declared section."),
        Rule("pe.section.header-overlap", RiskFeatureCategory.Structure, 20,
            "A section raw range overlaps the PE headers."),
        Rule("pe.section.raw-overlap", RiskFeatureCategory.Structure, 20,
            "Two or more section raw ranges overlap."),
        Rule("pe.section.virtual-overlap", RiskFeatureCategory.Structure, 20,
            "Two or more section virtual ranges overlap."),
        Rule("pe.sections.many", RiskFeatureCategory.Structure, 6,
            "The image contains an unusually large number of sections."),
        Rule("pe.section.write-execute", RiskFeatureCategory.Memory, 25,
            "A section is writable and executable."),
        Rule("pe.imports.process-injection", RiskFeatureCategory.Memory, 30,
            "Imported capabilities can manipulate or execute code in another process."),
        Rule("pe.section.executable-high-entropy", RiskFeatureCategory.Packing, 18,
            "An executable section has entropy consistent with compression or encryption."),
        Rule("pe.overlay.present", RiskFeatureCategory.Packing, 14,
            "The file contains substantial trailing data outside mapped sections."),
        Rule("pe.entrypoint.writable", RiskFeatureCategory.Execution, 15,
            "The entry point is located in a writable section."),
        Rule("pe.imports.dynamic-resolution", RiskFeatureCategory.Execution, 8,
            "Imported capabilities can resolve code dynamically at runtime."),
        Rule("pe.imports.none", RiskFeatureCategory.Execution, 6,
            "The image declares no normal or delay-loaded imports."),
        Rule("pe.imports.ordinal-heavy", RiskFeatureCategory.Execution, 8,
            "Most imported symbols are identified only by ordinal."),
        Rule("pe.tls.callbacks", RiskFeatureCategory.Execution, 7,
            "TLS callbacks can execute before the main entry point."),
        Rule("pe.imports.network", RiskFeatureCategory.Network, 12,
            "Imported capabilities can establish network or download activity."),
        Rule("pe.imports.persistence", RiskFeatureCategory.Persistence, 12,
            "Imported capabilities can modify services or persistent registry state."),
        Rule("pe.hardening.no-aslr", RiskFeatureCategory.Hardening, 4,
            "The image does not declare address-space layout randomization support."),
        Rule("pe.hardening.no-nx", RiskFeatureCategory.Hardening, 4,
            "The image does not declare data-execution prevention compatibility.")
    ];

    public static RiskScoringPolicy Default { get; } = new(
        "utoaegis.pe.default",
        policyVersion: 1,
        reviewThreshold: 35,
        detectionThreshold: 85,
        DefaultRules,
        DefaultCategoryCaps);

    public RiskScoringPolicy(
        string policyId,
        int policyVersion,
        int reviewThreshold,
        int detectionThreshold,
        IReadOnlyList<RiskScoringRule> rules,
        IReadOnlyDictionary<RiskFeatureCategory, int> categoryCaps,
        int schemaVersion = CurrentSchemaVersion)
    {
        ValidatePolicyId(policyId);
        ArgumentOutOfRangeException.ThrowIfNotEqual(schemaVersion, CurrentSchemaVersion);
        ArgumentOutOfRangeException.ThrowIfLessThan(policyVersion, 1);

        if (reviewThreshold is < 1 or > 99 ||
            detectionThreshold is < 2 or > 100 ||
            reviewThreshold >= detectionThreshold)
        {
            throw new ArgumentException(
                "Risk thresholds must be increasing values within the 1-100 score range.");
        }

        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(categoryCaps);
        if (rules.Count is < 1 or > MaximumRuleCount)
        {
            throw new ArgumentOutOfRangeException(nameof(rules));
        }

        var copiedRules = rules.ToArray();
        if (copiedRules.Any(rule => rule is null) ||
            copiedRules.Select(rule => rule.FeatureId).Distinct(StringComparer.Ordinal).Count() !=
            copiedRules.Length)
        {
            throw new ArgumentException("Risk policy rules must have unique feature IDs.", nameof(rules));
        }

        var copiedCaps = new Dictionary<RiskFeatureCategory, int>();
        foreach (var category in Enum.GetValues<RiskFeatureCategory>())
        {
            if (!categoryCaps.TryGetValue(category, out var cap) || cap is < 1 or > 100)
            {
                throw new ArgumentException(
                    "Risk policies require a bounded cap for every feature category.",
                    nameof(categoryCaps));
            }

            copiedCaps.Add(category, cap);
        }

        if (categoryCaps.Count != copiedCaps.Count)
        {
            throw new ArgumentException("Risk policy category caps contain an unknown category.", nameof(categoryCaps));
        }

        SchemaVersion = schemaVersion;
        PolicyId = policyId;
        PolicyVersion = policyVersion;
        ReviewThreshold = reviewThreshold;
        DetectionThreshold = detectionThreshold;
        Rules = copiedRules;
        CategoryCaps = copiedCaps;
    }

    public int SchemaVersion { get; }

    public string PolicyId { get; }

    public int PolicyVersion { get; }

    public int ReviewThreshold { get; }

    public int DetectionThreshold { get; }

    public IReadOnlyList<RiskScoringRule> Rules { get; }

    public IReadOnlyDictionary<RiskFeatureCategory, int> CategoryCaps { get; }

    private static RiskScoringRule Rule(
        string id,
        RiskFeatureCategory category,
        int weight,
        string explanation) =>
        new(id, category, weight, explanation);

    private static void ValidatePolicyId(string policyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyId);
        if (policyId.Length > MaximumPolicyIdLength ||
            policyId.Any(character =>
                character is not (>= 'a' and <= 'z') &&
                !char.IsAsciiDigit(character) &&
                character is not '.' and not '-'))
        {
            throw new ArgumentException(
                "Risk policy IDs must use bounded lowercase ASCII identifiers.",
                nameof(policyId));
        }
    }
}
