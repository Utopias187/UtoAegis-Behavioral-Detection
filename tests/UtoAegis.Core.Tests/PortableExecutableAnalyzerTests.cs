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

        Assert.AreEqual(PortableExecutableAnalysisStatus.Analyzed, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.None, result.IssueCode);
        Assert.IsNotNull(result.Header);
        Assert.IsGreaterThan(0, result.Header.SectionCount);
        Assert.IsLessThanOrEqualTo(16, result.Header.DataDirectoryCount);
        Assert.IsGreaterThan(0L, result.FileSizeBytes);
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
}
