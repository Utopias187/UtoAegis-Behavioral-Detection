using UtoAegis.Core.PortableExecutable;

namespace UtoAegis.Core.RiskScoring;

public sealed class PortableExecutableRiskFeatureExtractor
{
    public const int MaximumFeatureCount = 32;

    private const uint ImageDllCharacteristicsDynamicBase = 0x0040;
    private const uint ImageDllCharacteristicsNxCompatible = 0x0100;
    private const uint ImageScnMemExecute = 0x20000000;
    private const uint ImageScnMemWrite = 0x80000000;

    private static readonly HashSet<string> ProcessInjectionImports = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "createremotethread",
        "ntcreatethreadex",
        "ntunmapviewofsection",
        "ntwritevirtualmemory",
        "queueuserapc",
        "resumethread",
        "setthreadcontext",
        "virtualalloc",
        "virtualallocex",
        "virtualprotect",
        "virtualprotectex",
        "writeprocessmemory"
    };

    private static readonly HashSet<string> DynamicResolutionImports = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "getmodulehandlea",
        "getmodulehandlew",
        "getprocaddress",
        "ldrgetprocedureaddress",
        "ldrloaddll",
        "loadlibrarya",
        "loadlibraryexw",
        "loadlibraryw"
    };

    private static readonly HashSet<string> NetworkImports = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "connect",
        "httpsendrequesta",
        "httpsendrequestw",
        "internetopena",
        "internetopenw",
        "urldownloadtofilea",
        "urldownloadtofilew",
        "winhttpconnect",
        "winhttpopen",
        "winhttpsendrequest",
        "wsastartup"
    };

    private static readonly HashSet<string> PersistenceImports = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "changeserviceconfiga",
        "changeserviceconfigw",
        "createservicea",
        "createservicew",
        "regcreatekeyexa",
        "regcreatekeyexw",
        "regsetvalueexa",
        "regsetvalueexw",
        "startservicea",
        "startservicew"
    };

    public static IReadOnlyList<RiskFeature> Extract(PortableExecutableAnalysisResult analysis)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        if (analysis.Status == PortableExecutableAnalysisStatus.Malformed)
        {
            return [new RiskFeature("pe.analysis.malformed", RiskFeatureCategory.Structure, 100)];
        }

        if (analysis.Status != PortableExecutableAnalysisStatus.Analyzed || analysis.Header is null)
        {
            return [];
        }

        var features = new Dictionary<string, RiskFeature>(StringComparer.Ordinal);
        AddSectionFeatures(analysis, features);
        AddImportFeatures(analysis, features);
        AddPlatformFeatures(analysis, features);
        AddImageFeatures(analysis, features);
        AddHardeningFeatures(analysis, features);
        if (features.Count > MaximumFeatureCount)
        {
            throw new InvalidOperationException("The PE feature extractor exceeded its feature bound.");
        }

        return features.Values.OrderBy(feature => feature.Id, StringComparer.Ordinal).ToArray();
    }

    private static void AddSectionFeatures(
        PortableExecutableAnalysisResult analysis,
        IDictionary<string, RiskFeature> features)
    {
        AddIf(
            analysis.Sections.Any(section => section.RawRangeOverlapsAnotherSection),
            features,
            "pe.section.raw-overlap",
            RiskFeatureCategory.Structure,
            100);
        AddIf(
            analysis.Sections.Any(section => section.VirtualRangeOverlapsAnotherSection),
            features,
            "pe.section.virtual-overlap",
            RiskFeatureCategory.Structure,
            100);
        AddIf(
            analysis.Sections.Any(section => section.RawRangeOverlapsHeaders),
            features,
            "pe.section.header-overlap",
            RiskFeatureCategory.Structure,
            100);
        AddIf(
            analysis.Header!.EntryPointRva != 0 &&
            !analysis.Sections.Any(section => section.ContainsEntryPoint),
            features,
            "pe.entrypoint.unmapped",
            RiskFeatureCategory.Structure,
            100);
        AddIf(
            analysis.Sections.Count > 12,
            features,
            "pe.sections.many",
            RiskFeatureCategory.Structure,
            Scale(analysis.Sections.Count - 12, 12));

        var writableExecutable = analysis.Sections.Any(section =>
            (section.Characteristics & (ImageScnMemExecute | ImageScnMemWrite)) ==
            (ImageScnMemExecute | ImageScnMemWrite));
        AddIf(
            writableExecutable,
            features,
            "pe.section.write-execute",
            RiskFeatureCategory.Memory,
            100);

        var entryPointWritable = analysis.Sections.Any(section =>
            section.ContainsEntryPoint && (section.Characteristics & ImageScnMemWrite) != 0);
        AddIf(
            entryPointWritable,
            features,
            "pe.entrypoint.writable",
            RiskFeatureCategory.Execution,
            100);

        var maximumExecutableEntropy = analysis.Sections
            .Where(section => (section.Characteristics & ImageScnMemExecute) != 0)
            .Select(section => section.Entropy)
            .DefaultIfEmpty(0)
            .Max();
        AddIf(
            maximumExecutableEntropy >= 7.2,
            features,
            "pe.section.executable-high-entropy",
            RiskFeatureCategory.Packing,
            25 + checked((int)Math.Round(
                Math.Clamp((maximumExecutableEntropy - 7.2) / 0.8, 0, 1) * 75,
                MidpointRounding.AwayFromZero)));
    }

    private static void AddImportFeatures(
        PortableExecutableAnalysisResult analysis,
        IDictionary<string, RiskFeature> features)
    {
        var imports = analysis.DirectoryFacts.Imports
            .Concat(analysis.DirectoryFacts.DelayImports)
            .ToArray();
        AddIf(
            imports.Length == 0,
            features,
            "pe.imports.none",
            RiskFeatureCategory.Execution,
            40);

        var symbols = imports
            .Select(imported => imported.SymbolName)
            .Where(symbol => symbol is not null)
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        AddCapability(
            symbols.Count(ProcessInjectionImports.Contains),
            features,
            "pe.imports.process-injection",
            RiskFeatureCategory.Memory);
        AddCapability(
            symbols.Count(DynamicResolutionImports.Contains),
            features,
            "pe.imports.dynamic-resolution",
            RiskFeatureCategory.Execution);
        AddCapability(
            symbols.Count(NetworkImports.Contains),
            features,
            "pe.imports.network",
            RiskFeatureCategory.Network);
        AddCapability(
            symbols.Count(PersistenceImports.Contains),
            features,
            "pe.imports.persistence",
            RiskFeatureCategory.Persistence);

        var ordinalCount = imports.Count(imported => imported.Ordinal is not null);
        AddIf(
            imports.Length >= 4 && ordinalCount * 2 > imports.Length,
            features,
            "pe.imports.ordinal-heavy",
            RiskFeatureCategory.Execution,
            checked((ordinalCount * 100) / imports.Length));
    }

    private static void AddPlatformFeatures(
        PortableExecutableAnalysisResult analysis,
        IDictionary<string, RiskFeature> features)
    {
        var callbackCount = analysis.PlatformFacts.Tls?.CallbackRvas.Count ?? 0;
        AddIf(
            callbackCount > 0,
            features,
            "pe.tls.callbacks",
            RiskFeatureCategory.Execution,
            Scale(callbackCount, 4));
    }

    private static void AddImageFeatures(
        PortableExecutableAnalysisResult analysis,
        IDictionary<string, RiskFeature> features)
    {
        var overlaySize = analysis.ImageFacts.Overlay.OverlaySize;
        if (overlaySize < 4_096)
        {
            return;
        }

        var denominator = Math.Max(1L, analysis.FileSizeBytes);
        var ratioStrength = checked((int)Math.Min(100, (overlaySize * 400) / denominator));
        AddIf(
            true,
            features,
            "pe.overlay.present",
            RiskFeatureCategory.Packing,
            Math.Max(25, ratioStrength));
    }

    private static void AddHardeningFeatures(
        PortableExecutableAnalysisResult analysis,
        IDictionary<string, RiskFeature> features)
    {
        var characteristics = analysis.Header!.DllCharacteristics;
        AddIf(
            (characteristics & ImageDllCharacteristicsDynamicBase) == 0,
            features,
            "pe.hardening.no-aslr",
            RiskFeatureCategory.Hardening,
            100);
        AddIf(
            (characteristics & ImageDllCharacteristicsNxCompatible) == 0,
            features,
            "pe.hardening.no-nx",
            RiskFeatureCategory.Hardening,
            100);
    }

    private static void AddCapability(
        int matchCount,
        IDictionary<string, RiskFeature> features,
        string id,
        RiskFeatureCategory category) =>
        AddIf(matchCount > 0, features, id, category, Scale(matchCount, 4));

    private static int Scale(int value, int fullStrengthValue) =>
        Math.Clamp(checked((value * 100) / fullStrengthValue), 1, 100);

    private static void AddIf(
        bool condition,
        IDictionary<string, RiskFeature> features,
        string id,
        RiskFeatureCategory category,
        int strength)
    {
        if (condition)
        {
            features.Add(id, new RiskFeature(id, category, strength));
        }
    }
}
