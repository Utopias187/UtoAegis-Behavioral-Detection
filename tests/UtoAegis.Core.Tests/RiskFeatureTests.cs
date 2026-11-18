using UtoAegis.Core.PortableExecutable;
using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class RiskFeatureTests
{
    private static readonly string[] ExpectedSuspiciousFeatureIds =
    [
        "pe.entrypoint.writable",
        "pe.hardening.no-aslr",
        "pe.hardening.no-nx",
        "pe.imports.dynamic-resolution",
        "pe.imports.network",
        "pe.imports.persistence",
        "pe.imports.process-injection",
        "pe.overlay.present",
        "pe.section.executable-high-entropy",
        "pe.section.raw-overlap",
        "pe.section.write-execute",
        "pe.tls.callbacks"
    ];

    [TestMethod]
    public void Constructor_InvalidIdentifier_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new RiskFeature("PE Invalid", RiskFeatureCategory.Structure, 50));
    }

    [TestMethod]
    public void Constructor_InvalidStrength_Throws()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new RiskFeature("pe.valid", RiskFeatureCategory.Structure, 0));
    }

    [TestMethod]
    public void Extract_MalformedImage_ReturnsSingleStructuralFeature()
    {
        var features = PortableExecutableRiskFeatureExtractor.Extract(
            EmptyResult(PortableExecutableAnalysisStatus.Malformed));

        Assert.HasCount(1, features);
        Assert.AreEqual("pe.analysis.malformed", features[0].Id);
        Assert.AreEqual(100, features[0].Strength);
    }

    [TestMethod]
    public void Extract_NonPortableExecutable_ReturnsNoFeatures()
    {
        var features = PortableExecutableRiskFeatureExtractor.Extract(
            EmptyResult(PortableExecutableAnalysisStatus.NotPortableExecutable));

        Assert.IsEmpty(features);
    }

    [TestMethod]
    public void Extract_SuspiciousFacts_ReturnsSortedNormalizedFeatures()
    {
        var analysis = CreateSuspiciousResult();

        var features = PortableExecutableRiskFeatureExtractor.Extract(analysis);

        Assert.IsLessThanOrEqualTo(
            PortableExecutableRiskFeatureExtractor.MaximumFeatureCount,
            features.Count);
        CollectionAssert.AreEqual(
            features.Select(feature => feature.Id).Order(StringComparer.Ordinal).ToArray(),
            features.Select(feature => feature.Id).ToArray());
        CollectionAssert.IsSubsetOf(
            ExpectedSuspiciousFeatureIds,
            features.Select(feature => feature.Id).ToArray());
        Assert.IsTrue(features.All(feature => feature.Strength is >= 1 and <= 100));
    }

    [TestMethod]
    public async Task Extract_ManagedTestAssembly_IsDeterministicAndBounded()
    {
        var analysis = await new PortableExecutableAnalyzer().AnalyzeAsync(
            typeof(RiskFeatureTests).Assembly.Location);
        var first = PortableExecutableRiskFeatureExtractor.Extract(analysis);
        var second = PortableExecutableRiskFeatureExtractor.Extract(analysis);

        CollectionAssert.AreEqual(first.ToArray(), second.ToArray());
        Assert.IsLessThanOrEqualTo(
            PortableExecutableRiskFeatureExtractor.MaximumFeatureCount,
            first.Count);
    }

    private static PortableExecutableAnalysisResult CreateSuspiciousResult()
    {
        var section = new PortableExecutableSection(
            ".text",
            0x2000,
            0x1000,
            0x400,
            0x1000,
            0xa0000020,
            7.9,
            IsRawRangeAligned: true,
            IsVirtualAddressAligned: true,
            RawRangeOverlapsHeaders: false,
            RawRangeOverlapsAnotherSection: true,
            VirtualRangeOverlapsAnotherSection: false,
            ContainsEntryPoint: true);
        var imports = new[]
        {
            Import("VirtualAlloc"),
            Import("WriteProcessMemory"),
            Import("CreateRemoteThread"),
            Import("GetProcAddress"),
            Import("URLDownloadToFileW"),
            Import("RegSetValueExW")
        };
        return new PortableExecutableAnalysisResult(
            PortableExecutableAnalysisStatus.Analyzed,
            100_000,
            new PortableExecutableHeader(
                PortableExecutableFormat.Pe32Plus,
                0x8664,
                0,
                0,
                3,
                0,
                0x140000000,
                0x2000,
                0x1000,
                0x200,
                0x4000,
                0x400,
                0,
                1,
                16),
            [section],
            new PortableExecutableDirectoryFacts(imports, [], [], []),
            new PortableExecutablePlatformFacts(
                [],
                new PortableExecutableTlsFacts(0, 0, 0, 0x3000, 0, 0, [0x2100]),
                null,
                [],
                null),
            new PortableExecutableImageFacts(
                null,
                [],
                new PortableExecutableOverlayFacts(80_000, 20_000, 0, 20_000)),
            PortableExecutableIssueCode.None);
    }

    private static PortableExecutableImport Import(string symbol) =>
        new("kernel32.dll", symbol, null, 0, IsDelayLoaded: false);

    private static PortableExecutableAnalysisResult EmptyResult(
        PortableExecutableAnalysisStatus status) =>
        new(
            status,
            100,
            null,
            [],
            PortableExecutableDirectoryFacts.Empty,
            PortableExecutablePlatformFacts.Empty,
            PortableExecutableImageFacts.Empty,
            status == PortableExecutableAnalysisStatus.Malformed
                ? PortableExecutableIssueCode.InvalidHeaders
                : PortableExecutableIssueCode.NotPortableExecutable);
}
