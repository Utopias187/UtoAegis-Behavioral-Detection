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
        Assert.IsTrue(result.DirectoryFacts.Imports.Any(imported =>
            string.Equals(imported.ModuleName, "mscoree.dll", StringComparison.OrdinalIgnoreCase)));
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
        Assert.IsGreaterThanOrEqualTo(3, sectionCount);
        var firstRawOffset = BinaryPrimitives.ReadUInt32LittleEndian(
            bytes.AsSpan(sectionTable + 20, 4));
        var third = sectionTable + 80;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(third + 20, 4), firstRawOffset);
        ClearDirectory(bytes, 5);
        var path = Path.Combine(testDirectory, "overlap.dll");
        await File.WriteAllBytesAsync(path, bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.IsTrue(result.Sections[0].RawRangeOverlapsAnotherSection);
        Assert.IsTrue(result.Sections[2].RawRangeOverlapsAnotherSection);
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
        ClearDirectory(bytes, 5);
        var path = Path.Combine(testDirectory, "zero-section.dll");
        await File.WriteAllBytesAsync(path, bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.AreEqual(0d, result.Sections[^1].Entropy);
    }

    [TestMethod]
    public async Task AnalyzeAsync_InjectedDelayImport_ExtractsBoundedSymbol()
    {
        var bytes = await LoadFixtureAsync();
        var layout = GetLastSectionLayout(bytes);
        Assert.IsFalse(layout.IsPe32Plus);
        bytes.AsSpan(layout.RawOffset, layout.RawSize).Clear();
        WriteUInt32(bytes, layout.RawOffset, 1);
        WriteUInt32(bytes, layout.RawOffset + 4, layout.Rva + 64);
        WriteUInt32(bytes, layout.RawOffset + 16, layout.Rva + 80);
        WriteAscii(bytes, layout.RawOffset + 64, "fixture.dll");
        WriteUInt32(bytes, layout.RawOffset + 80, layout.Rva + 96);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(layout.RawOffset + 96, 2), 7);
        WriteAscii(bytes, layout.RawOffset + 98, "Delayed");
        WriteDirectory(bytes, layout, 13, layout.Rva, 64);
        var path = await WriteFixtureAsync("delay-import.dll", bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.HasCount(1, result.DirectoryFacts.DelayImports);
        var imported = result.DirectoryFacts.DelayImports[0];
        Assert.AreEqual("fixture.dll", imported.ModuleName);
        Assert.AreEqual("Delayed", imported.SymbolName);
        Assert.AreEqual((ushort)7, imported.Hint);
        Assert.IsTrue(imported.IsDelayLoaded);
    }

    [TestMethod]
    public async Task AnalyzeAsync_InjectedExport_ExtractsNameAndOrdinal()
    {
        var bytes = await LoadFixtureAsync();
        var layout = GetLastSectionLayout(bytes);
        bytes.AsSpan(layout.RawOffset, layout.RawSize).Clear();
        WriteUInt32(bytes, layout.RawOffset + 12, layout.Rva + 64);
        WriteUInt32(bytes, layout.RawOffset + 16, 1);
        WriteUInt32(bytes, layout.RawOffset + 20, 1);
        WriteUInt32(bytes, layout.RawOffset + 24, 1);
        WriteUInt32(bytes, layout.RawOffset + 28, layout.Rva + 40);
        WriteUInt32(bytes, layout.RawOffset + 32, layout.Rva + 44);
        WriteUInt32(bytes, layout.RawOffset + 36, layout.Rva + 48);
        WriteUInt32(bytes, layout.RawOffset + 40, GetFirstSectionRva(bytes));
        WriteUInt32(bytes, layout.RawOffset + 44, layout.Rva + 50);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(layout.RawOffset + 48, 2), 0);
        WriteAscii(bytes, layout.RawOffset + 50, "TestExport");
        WriteAscii(bytes, layout.RawOffset + 64, "fixture.dll");
        WriteDirectory(bytes, layout, 0, layout.Rva, 80);
        var path = await WriteFixtureAsync("export.dll", bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.HasCount(1, result.DirectoryFacts.Exports);
        var exported = result.DirectoryFacts.Exports[0];
        Assert.AreEqual("TestExport", exported.Name);
        Assert.AreEqual(1u, exported.Ordinal);
        Assert.IsNull(exported.Forwarder);
    }

    [TestMethod]
    public async Task AnalyzeAsync_InjectedResource_ExtractsTypeNameAndLanguage()
    {
        var bytes = await LoadFixtureAsync();
        var layout = GetLastSectionLayout(bytes);
        bytes.AsSpan(layout.RawOffset, layout.RawSize).Clear();
        WriteResourceDirectory(bytes, layout.RawOffset, 1);
        WriteUInt32(bytes, layout.RawOffset + 16, 10);
        WriteUInt32(bytes, layout.RawOffset + 20, 0x80000018);
        WriteResourceDirectory(bytes, layout.RawOffset + 24, 1);
        WriteUInt32(bytes, layout.RawOffset + 40, 1);
        WriteUInt32(bytes, layout.RawOffset + 44, 0x80000030);
        WriteResourceDirectory(bytes, layout.RawOffset + 48, 1);
        WriteUInt32(bytes, layout.RawOffset + 64, 1033);
        WriteUInt32(bytes, layout.RawOffset + 68, 72);
        WriteUInt32(bytes, layout.RawOffset + 72, GetFirstSectionRva(bytes));
        WriteUInt32(bytes, layout.RawOffset + 76, 4);
        WriteUInt32(bytes, layout.RawOffset + 80, 1200);
        WriteDirectory(bytes, layout, 2, layout.Rva, 88);
        var path = await WriteFixtureAsync("resource.dll", bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.HasCount(1, result.DirectoryFacts.Resources);
        var resource = result.DirectoryFacts.Resources[0];
        Assert.AreEqual("#10", resource.Type);
        Assert.AreEqual("#1", resource.Name);
        Assert.AreEqual("#1033", resource.Language);
        Assert.AreEqual(1200u, resource.CodePage);
    }

    [TestMethod]
    public async Task AnalyzeAsync_CyclicResourceDirectory_ReturnsMalformed()
    {
        var bytes = await LoadFixtureAsync();
        var layout = GetLastSectionLayout(bytes);
        bytes.AsSpan(layout.RawOffset, layout.RawSize).Clear();
        WriteResourceDirectory(bytes, layout.RawOffset, 1);
        WriteUInt32(bytes, layout.RawOffset + 16, 10);
        WriteUInt32(bytes, layout.RawOffset + 20, 0x80000000);
        WriteDirectory(bytes, layout, 2, layout.Rva, 24);
        var path = await WriteFixtureAsync("cyclic-resource.dll", bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(PortableExecutableAnalysisStatus.Malformed, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.InvalidResourceTable, result.IssueCode);
    }

    [TestMethod]
    public async Task AnalyzeAsync_InjectedPlatformDirectories_ExtractsBoundedFacts()
    {
        var bytes = await LoadFixtureAsync();
        var layout = GetLastSectionLayout(bytes);
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c, 4));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(peOffset + 4, 2), 0x8664);
        bytes.AsSpan(layout.RawOffset, layout.RawSize).Clear();
        var imageBase = GetPe32ImageBase(bytes);
        var firstSectionRva = GetFirstSectionRva(bytes);

        WriteUInt32(bytes, layout.RawOffset + 4, 1234);
        WriteUInt16(bytes, layout.RawOffset + 8, 2);
        WriteUInt16(bytes, layout.RawOffset + 10, 1);
        WriteUInt32(bytes, layout.RawOffset + 12, 2);
        WriteDirectory(bytes, layout, 6, layout.Rva, 28);

        WriteUInt32(bytes, layout.RawOffset + 32, imageBase + firstSectionRva);
        WriteUInt32(bytes, layout.RawOffset + 36, imageBase + firstSectionRva + 4);
        WriteUInt32(bytes, layout.RawOffset + 40, imageBase + firstSectionRva);
        WriteUInt32(bytes, layout.RawOffset + 44, imageBase + layout.Rva + 64);
        WriteUInt32(bytes, layout.RawOffset + 64, imageBase + firstSectionRva);
        WriteDirectory(bytes, layout, 9, layout.Rva + 32, 24);

        WriteUInt32(bytes, layout.RawOffset + 80, 92);
        WriteUInt32(bytes, layout.RawOffset + 84, 5678);
        WriteUInt16(bytes, layout.RawOffset + 88, 3);
        WriteUInt16(bytes, layout.RawOffset + 90, 4);
        WriteUInt32(bytes, layout.RawOffset + 92, 1);
        WriteUInt32(bytes, layout.RawOffset + 96, 2);
        WriteUInt32(bytes, layout.RawOffset + 100, 30);
        WriteUInt32(bytes, layout.RawOffset + 140, imageBase + firstSectionRva);
        WriteUInt32(bytes, layout.RawOffset + 148, 2);
        WriteUInt32(bytes, layout.RawOffset + 168, 0x100);
        WriteDirectory(bytes, layout, 10, layout.Rva + 80, 92);

        WriteUInt32(bytes, layout.RawOffset + 176, firstSectionRva);
        WriteUInt32(bytes, layout.RawOffset + 180, 12);
        WriteUInt16(bytes, layout.RawOffset + 184, 0x3004);
        WriteDirectory(bytes, layout, 5, layout.Rva + 176, 12);

        WriteUInt32(bytes, layout.RawOffset + 192, firstSectionRva);
        WriteUInt32(bytes, layout.RawOffset + 196, firstSectionRva + 16);
        WriteUInt32(bytes, layout.RawOffset + 200, firstSectionRva + 32);
        WriteDirectory(bytes, layout, 3, layout.Rva + 192, 12);
        var path = await WriteFixtureAsync("platform-directories.dll", bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(
            PortableExecutableAnalysisStatus.Analyzed,
            result.Status,
            $"Issue: {result.IssueCode}");
        Assert.HasCount(1, result.PlatformFacts.DebugEntries);
        Assert.AreEqual(2u, result.PlatformFacts.DebugEntries[0].Type);
        Assert.IsNotNull(result.PlatformFacts.Tls);
        CollectionAssert.AreEqual(
            new[] { firstSectionRva },
            result.PlatformFacts.Tls.CallbackRvas.ToArray());
        Assert.IsNotNull(result.PlatformFacts.LoadConfiguration);
        Assert.AreEqual(0x100u, result.PlatformFacts.LoadConfiguration.GuardFlags);
        Assert.HasCount(2, result.PlatformFacts.Relocations);
        Assert.AreEqual((ushort)3, result.PlatformFacts.Relocations[0].Type);
        Assert.IsNotNull(result.PlatformFacts.Exceptions);
        Assert.HasCount(1, result.PlatformFacts.Exceptions.Entries);
        Assert.AreEqual(firstSectionRva + 16, result.PlatformFacts.Exceptions.Entries[0].EndRva);
    }

    [TestMethod]
    public async Task AnalyzeAsync_InvalidRelocationBlock_ReturnsMalformed()
    {
        var bytes = await LoadFixtureAsync();
        var layout = GetLastSectionLayout(bytes);
        bytes.AsSpan(layout.RawOffset, layout.RawSize).Clear();
        WriteUInt32(bytes, layout.RawOffset, GetFirstSectionRva(bytes));
        WriteUInt32(bytes, layout.RawOffset + 4, 16);
        WriteDirectory(bytes, layout, 5, layout.Rva, 12);
        var path = await WriteFixtureAsync("invalid-relocations.dll", bytes);

        var result = await new PortableExecutableAnalyzer().AnalyzeAsync(path);

        Assert.AreEqual(PortableExecutableAnalysisStatus.Malformed, result.Status);
        Assert.AreEqual(PortableExecutableIssueCode.InvalidRelocationTable, result.IssueCode);
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

    private static Task<byte[]> LoadFixtureAsync() =>
        File.ReadAllBytesAsync(typeof(PortableExecutableAnalyzerTests).Assembly.Location);

    private async Task<string> WriteFixtureAsync(string name, byte[] bytes)
    {
        var path = Path.Combine(testDirectory, name);
        await File.WriteAllBytesAsync(path, bytes);
        return path;
    }

    private static PeFixtureLayout GetLastSectionLayout(byte[] bytes)
    {
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c, 4));
        var optionalOffset = peOffset + 24;
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(optionalOffset, 2));
        var isPe32Plus = magic == 0x20b;
        var sectionTable = GetSectionTableOffset(bytes);
        var section = sectionTable + ((GetSectionCount(bytes) - 1) * 40);
        var rawSize = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(
            bytes.AsSpan(section + 16, 4)));
        WriteUInt32(bytes, section + 8, checked((uint)rawSize));
        var layout = new PeFixtureLayout(
            optionalOffset + (isPe32Plus ? 112 : 96),
            checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(section + 20, 4))),
            rawSize,
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(section + 12, 4)),
            isPe32Plus);
        WriteDirectory(bytes, layout, 5, 0, 0);
        return layout;
    }

    private static uint GetFirstSectionRva(byte[] bytes) =>
        BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(GetSectionTableOffset(bytes) + 12, 4));

    private static uint GetPe32ImageBase(byte[] bytes)
    {
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c, 4));
        var optionalOffset = peOffset + 24;
        Assert.AreEqual((ushort)0x10b, BinaryPrimitives.ReadUInt16LittleEndian(
            bytes.AsSpan(optionalOffset, 2)));
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(optionalOffset + 28, 4));
    }

    private static void WriteDirectory(
        byte[] bytes,
        PeFixtureLayout layout,
        int index,
        uint rva,
        uint size)
    {
        var offset = layout.DirectoryOffset + (index * 8);
        WriteUInt32(bytes, offset, rva);
        WriteUInt32(bytes, offset + 4, size);
    }

    private static void ClearDirectory(byte[] bytes, int index)
    {
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c, 4));
        var optionalOffset = peOffset + 24;
        var isPe32Plus = BinaryPrimitives.ReadUInt16LittleEndian(
            bytes.AsSpan(optionalOffset, 2)) == 0x20b;
        var offset = optionalOffset + (isPe32Plus ? 112 : 96) + (index * 8);
        bytes.AsSpan(offset, 8).Clear();
    }

    private static void WriteResourceDirectory(byte[] bytes, int offset, ushort idCount) =>
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset + 14, 2), idCount);

    private static void WriteUInt32(byte[] bytes, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset, 4), value);

    private static void WriteUInt16(byte[] bytes, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset, 2), value);

    private static void WriteAscii(byte[] bytes, int offset, string value)
    {
        var encoded = System.Text.Encoding.ASCII.GetBytes(value);
        encoded.CopyTo(bytes, offset);
        bytes[offset + encoded.Length] = 0;
    }

    private sealed record PeFixtureLayout(
        int DirectoryOffset,
        int RawOffset,
        int RawSize,
        uint Rva,
        bool IsPe32Plus);
}
