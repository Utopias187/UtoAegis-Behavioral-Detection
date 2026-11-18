using System.Buffers.Binary;
using UtoAegis.Core.PortableExecutable;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class PortableExecutableAnalyzerTests
{
    private string testDirectory = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.PE.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDirectory);
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task AnalyzeAsync_ManagedTestAssembly_ExtractsBoundedHeaders()
    {
        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(
            typeof(PortableExecutableAnalyzerTests).Assembly.Location);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.AreEqual(PortableExecutableIssueCode.None, result.IssueCode);
        Assert.IsNotNull(result.Header);
        Assert.IsGreaterThan(0, result.Header.SectionCount);
        Assert.IsLessThanOrEqualTo(16, result.Header.DataDirectoryCount);
        Assert.IsGreaterThan(0L, result.FileSizeBytes);
        Assert.HasCount(result.Header.SectionCount, result.Sections);
        Assert.IsTrue(result.Sections.All(section =>
            section.Entropy is >= 0 and <= 8 &&
            section.Name.Length <= 8 &&
            (ulong)section.RawDataOffset + section.RawDataSize <= (ulong)result.FileSizeBytes));
    }

    [TestMethod]
    public async Task AnalyzeAsync_TextFile_ReturnsNotPortableExecutable()
    {
        var path = Path.Combine(testDirectory, "sample.txt");
        await File.WriteAllTextAsync(path, "ordinary text");

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(PortableExecutableAnalysisStatus.NotPortableExecutable, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.NotPortableExecutable, result.IssueCode);
        Assert.IsNull(result.Header);
    }

    [TestMethod]
    public async Task AnalyzeAsync_TruncatedMzHeader_ReturnsMalformed()
    {
        var path = Path.Combine(testDirectory, "truncated.exe");
        await File.WriteAllBytesAsync(path, [(byte)'M', (byte)'Z', 0, 0]);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(PortableExecutableAnalysisStatus.Malformed, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.TruncatedHeaders, result.IssueCode);
    }

    [TestMethod]
    public async Task AnalyzeAsync_InvalidPeOffset_ReturnsMalformed()
    {
        var bytes = new byte[128];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(int.MaxValue).CopyTo(bytes, 0x3c);
        var path = Path.Combine(testDirectory, "invalid.exe");
        await File.WriteAllBytesAsync(path, bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(PortableExecutableAnalysisStatus.Malformed, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.InvalidHeaders, result.IssueCode);
    }

    [TestMethod]
    public async Task AnalyzeAsync_EmptyFile_ReturnsUnsafeInput()
    {
        var path = Path.Combine(testDirectory, "empty.exe");
        await File.WriteAllBytesAsync(path, []);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(PortableExecutableAnalysisStatus.UnsafeInput, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.EmptyFile, result.IssueCode);
    }

    [TestMethod]
    public async Task AnalyzeAsync_OverConfiguredLimit_ReturnsUnsafeInput()
    {
        var path = Path.Combine(testDirectory, "large.exe");
        await File.WriteAllBytesAsync(path, new byte[65]);
        var analyzer = new PortableExecutableAnalyzer(
            new PortableExecutableAnalyzerOptions(maximumFileSizeBytes: 64));

        var result = await analyzer.AnalyzeAsync(path);

        Assert.AreEqual(PortableExecutableAnalysisStatus.UnsafeInput, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.FileTooLarge, result.IssueCode);
    }

    [TestMethod]
    public async Task AnalyzeAsync_RawSectionOutsideFile_ReturnsMalformed()
    {
        var bytes = await File.ReadAllBytesAsync(
            typeof(PortableExecutableAnalyzerTests).Assembly.Location);
        var sectionTable = GetSectionTableOffset(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(sectionTable + 16, 4), uint.MaxValue);
        var path = Path.Combine(testDirectory, "raw-outside-file.dll");
        await File.WriteAllBytesAsync(path, bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(PortableExecutableAnalysisStatus.Malformed, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.SectionRangeOutOfBounds, result.IssueCode);
    }

    [TestMethod]
    public async Task AnalyzeAsync_OverlappingRawSections_RecordsBothSections()
    {
        var bytes = await File.ReadAllBytesAsync(
            typeof(PortableExecutableAnalyzerTests).Assembly.Location);
        var sectionTable = GetSectionTableOffset(bytes);
        var sectionCount = GetSectionCount(bytes);
        Assert.IsGreaterThanOrEqualTo(2, sectionCount);
        var firstRawOffset = BinaryPrimitives.ReadUInt32LittleEndian(
            bytes.AsSpan(sectionTable + 20, 4));
        var second = sectionTable + 40;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(second + 20, 4), firstRawOffset);
        var path = Path.Combine(testDirectory, "overlap.dll");
        await File.WriteAllBytesAsync(path, bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.IsTrue(result.Sections[0].RawRangeOverlapsAnotherSection);
        Assert.IsTrue(result.Sections[1].RawRangeOverlapsAnotherSection);
    }

    [TestMethod]
    public async Task AnalyzeAsync_ZeroFilledSection_ReturnsZeroEntropy()
    {
        var bytes = await File.ReadAllBytesAsync(
            typeof(PortableExecutableAnalyzerTests).Assembly.Location);
        var sectionTable = GetSectionTableOffset(bytes);
        var sectionCount = GetSectionCount(bytes);
        var lastSection = sectionTable + ((sectionCount - 1) * 40);
        var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(lastSection + 16, 4));
        var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(lastSection + 20, 4));
        bytes.AsSpan(checked((int)rawOffset), checked((int)rawSize)).Clear();
        var path = Path.Combine(testDirectory, "zero-section.dll");
        await File.WriteAllBytesAsync(path, bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.AreEqual(0d, result.Sections[^1].Entropy);
    }

    private static int GetSectionTableOffset(byte[] bytes)
    {
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c, 4));
        var optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(
            bytes.AsSpan(peOffset + 20, 2));
        return checked(peOffset + 24 + optionalHeaderSize);
    }

    private static int GetSectionCount(byte[] bytes)
    {
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c, 4));
        return BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(peOffset + 6, 2));
    }
}
