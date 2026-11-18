using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;

namespace UtoAegis.Core.PortableExecutable;

internal static class PortableExecutableDirectoryReader
{
    private const int MaximumDescriptorCount = 512;
    private const int MaximumAsciiNameLength = 512;
    private const int MaximumResourceNameLength = 128;
    private const int MaximumDirectorySize = 16 * 1024 * 1024;

    public static PortableExecutableDirectoryFacts Read(
        PEReader reader,
        PEHeader header,
        PortableExecutableAnalyzerOptions options)
    {
        try
        {
            var imports = ReadImports(
                reader,
                header.ImportTableDirectory,
                header.Magic == PEMagic.PE32Plus,
                options.MaximumImportCount,
                isDelayLoaded: false,
                PortableExecutableIssueCode.InvalidImportTable);
            var delayImports = ReadDelayImports(reader, header, options.MaximumImportCount);
            var exports = ReadExports(reader, header.ExportTableDirectory, options.MaximumExportCount);
            var resources = ReadResources(
                reader,
                header.ResourceTableDirectory,
                options.MaximumResourceCount);
            return new PortableExecutableDirectoryFacts(imports, delayImports, exports, resources);
        }
        catch (PortableExecutableDirectoryException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentOutOfRangeException or
                OverflowException or DecoderFallbackException)
        {
            throw new PortableExecutableDirectoryException(
                PortableExecutableIssueCode.InvalidHeaders,
                exception);
        }
    }

    private static List<PortableExecutableImport> ReadImports(
        PEReader reader,
        DirectoryEntry directory,
        bool isPe32Plus,
        int maximumCount,
        bool isDelayLoaded,
        PortableExecutableIssueCode issueCode)
    {
        if (IsEmpty(directory))
        {
            return [];
        }

        ValidateDirectory(directory, 20, MaximumDescriptorCount, issueCode);
        var imports = new List<PortableExecutableImport>();
        var descriptorCount = directory.Size / 20;
        var terminated = false;
        for (var index = 0; index < descriptorCount; index++)
        {
            var descriptor = GetReader(reader, checked(directory.RelativeVirtualAddress + (index * 20)), 20, issueCode);
            var lookupRva = descriptor.ReadUInt32();
            var timestamp = descriptor.ReadUInt32();
            var forwarderChain = descriptor.ReadUInt32();
            var nameRva = descriptor.ReadUInt32();
            var addressRva = descriptor.ReadUInt32();
            if ((lookupRva | timestamp | forwarderChain | nameRva | addressRva) == 0)
            {
                terminated = true;
                break;
            }

            if (nameRva == 0 || (lookupRva == 0 && addressRva == 0))
            {
                throw new PortableExecutableDirectoryException(issueCode);
            }

            var moduleName = ReadAscii(reader, nameRva, MaximumAsciiNameLength, issueCode);
            ReadThunkTable(
                reader,
                lookupRva == 0 ? addressRva : lookupRva,
                moduleName,
                isPe32Plus,
                maximumCount,
                isDelayLoaded,
                imports,
                issueCode);
        }

        if (!terminated)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        return imports;
    }

    private static List<PortableExecutableImport> ReadDelayImports(
        PEReader reader,
        PEHeader header,
        int maximumCount)
    {
        var directory = header.DelayImportTableDirectory;
        var issueCode = PortableExecutableIssueCode.InvalidDelayImportTable;
        if (IsEmpty(directory))
        {
            return [];
        }

        ValidateDirectory(directory, 32, MaximumDescriptorCount, issueCode);
        var imports = new List<PortableExecutableImport>();
        var descriptorCount = directory.Size / 32;
        var terminated = false;
        for (var index = 0; index < descriptorCount; index++)
        {
            var descriptor = GetReader(reader, checked(directory.RelativeVirtualAddress + (index * 32)), 32, issueCode);
            var attributes = descriptor.ReadUInt32();
            var name = descriptor.ReadUInt32();
            var moduleHandle = descriptor.ReadUInt32();
            var importAddressTable = descriptor.ReadUInt32();
            var importNameTable = descriptor.ReadUInt32();
            var boundTable = descriptor.ReadUInt32();
            var unloadTable = descriptor.ReadUInt32();
            var timestamp = descriptor.ReadUInt32();
            if ((attributes | name | moduleHandle | importAddressTable | importNameTable |
                 boundTable | unloadTable | timestamp) == 0)
            {
                terminated = true;
                break;
            }

            if ((attributes & ~1u) != 0 || name == 0 || importNameTable == 0)
            {
                throw new PortableExecutableDirectoryException(issueCode);
            }

            var nameRva = NormalizeDelayPointer(name, attributes, header.ImageBase, issueCode);
            var thunkRva = NormalizeDelayPointer(
                importNameTable,
                attributes,
                header.ImageBase,
                issueCode);
            var moduleName = ReadAscii(reader, nameRva, MaximumAsciiNameLength, issueCode);
            ReadThunkTable(
                reader,
                thunkRva,
                moduleName,
                header.Magic == PEMagic.PE32Plus,
                maximumCount,
                isDelayLoaded: true,
                imports,
                issueCode);
        }

        if (!terminated)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        return imports;
    }

    private static void ReadThunkTable(
        PEReader reader,
        uint tableRva,
        string moduleName,
        bool isPe32Plus,
        int maximumCount,
        bool isDelayLoaded,
        List<PortableExecutableImport> imports,
        PortableExecutableIssueCode issueCode)
    {
        var width = isPe32Plus ? 8 : 4;
        var block = reader.GetSectionData(checked((int)tableRva));
        if (block.Length < width)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var table = block.GetReader();
        var ordinalMask = isPe32Plus ? 0x8000000000000000UL : 0x80000000UL;
        var terminated = false;
        while (table.RemainingBytes >= width)
        {
            var value = isPe32Plus ? table.ReadUInt64() : table.ReadUInt32();
            if (value == 0)
            {
                terminated = true;
                break;
            }

            if (imports.Count >= maximumCount)
            {
                throw new PortableExecutableDirectoryException(
                    PortableExecutableIssueCode.DirectoryLimitExceeded);
            }

            if ((value & ordinalMask) != 0)
            {
                if ((value & ~(ordinalMask | 0xffffUL)) != 0)
                {
                    throw new PortableExecutableDirectoryException(issueCode);
                }

                imports.Add(new PortableExecutableImport(
                    moduleName,
                    null,
                    (ushort)value,
                    null,
                    isDelayLoaded));
                continue;
            }

            if (value > uint.MaxValue)
            {
                throw new PortableExecutableDirectoryException(issueCode);
            }

            var nameReader = GetReader(reader, checked((int)(uint)value), 2, issueCode);
            var hint = nameReader.ReadUInt16();
            var symbol = ReadAscii(
                reader,
                checked((uint)value + 2),
                MaximumAsciiNameLength,
                issueCode);
            imports.Add(new PortableExecutableImport(
                moduleName,
                symbol,
                null,
                hint,
                isDelayLoaded));
        }

        if (!terminated)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }
    }

    private static PortableExecutableExport[] ReadExports(
        PEReader reader,
        DirectoryEntry directory,
        int maximumCount)
    {
        var issueCode = PortableExecutableIssueCode.InvalidExportTable;
        if (IsEmpty(directory))
        {
            return [];
        }

        if (directory.RelativeVirtualAddress <= 0 || directory.Size < 40 ||
            directory.Size > MaximumDirectorySize)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        _ = checked(directory.RelativeVirtualAddress + directory.Size);
        var exportDirectory = GetReader(reader, directory.RelativeVirtualAddress, 40, issueCode);
        exportDirectory.Offset += 12;
        _ = exportDirectory.ReadUInt32();
        var ordinalBase = exportDirectory.ReadUInt32();
        var functionCount = exportDirectory.ReadUInt32();
        var nameCount = exportDirectory.ReadUInt32();
        var functionsRva = exportDirectory.ReadUInt32();
        var namesRva = exportDirectory.ReadUInt32();
        var ordinalsRva = exportDirectory.ReadUInt32();
        if (functionCount > maximumCount || nameCount > functionCount || nameCount > maximumCount)
        {
            throw new PortableExecutableDirectoryException(
                PortableExecutableIssueCode.DirectoryLimitExceeded);
        }

        var names = new Dictionary<int, string>();
        for (var index = 0; index < nameCount; index++)
        {
            var nameRva = ReadUInt32(reader, checked(namesRva + ((uint)index * 4)), issueCode);
            var functionIndex = ReadUInt16(
                reader,
                checked(ordinalsRva + ((uint)index * 2)),
                issueCode);
            if (functionIndex >= functionCount || !names.TryAdd(
                    functionIndex,
                    ReadAscii(reader, nameRva, MaximumAsciiNameLength, issueCode)))
            {
                throw new PortableExecutableDirectoryException(issueCode);
            }
        }

        var exports = new PortableExecutableExport[checked((int)functionCount)];
        var directoryStart = (uint)directory.RelativeVirtualAddress;
        var directoryEnd = checked(directoryStart + (uint)directory.Size);
        for (var index = 0; index < functionCount; index++)
        {
            var functionRva = ReadUInt32(
                reader,
                checked(functionsRva + ((uint)index * 4)),
                issueCode);
            var forwarder = functionRva >= directoryStart && functionRva < directoryEnd
                ? ReadAscii(reader, functionRva, MaximumAsciiNameLength, issueCode)
                : null;
            names.TryGetValue(index, out var name);
            exports[index] = new PortableExecutableExport(
                name,
                checked(ordinalBase + (uint)index),
                functionRva,
                forwarder);
        }

        return exports;
    }

    private static List<PortableExecutableResource> ReadResources(
        PEReader reader,
        DirectoryEntry directory,
        int maximumCount)
    {
        var issueCode = PortableExecutableIssueCode.InvalidResourceTable;
        if (IsEmpty(directory))
        {
            return [];
        }

        if (directory.RelativeVirtualAddress <= 0 || directory.Size < 16 ||
            directory.Size > MaximumDirectorySize)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var block = reader.GetSectionData(directory.RelativeVirtualAddress);
        if (block.Length < directory.Size)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var bytes = block.GetContent(0, directory.Size).ToArray();
        var resources = new List<PortableExecutableResource>();
        var visited = new HashSet<int>();
        WalkResourceDirectory(
            bytes,
            0,
            0,
            [],
            directory.RelativeVirtualAddress,
            reader,
            maximumCount,
            visited,
            resources,
            issueCode);
        return resources;
    }

    private static void WalkResourceDirectory(
        byte[] bytes,
        int offset,
        int depth,
        IReadOnlyList<string> path,
        int resourceRva,
        PEReader reader,
        int maximumCount,
        HashSet<int> visited,
        List<PortableExecutableResource> resources,
        PortableExecutableIssueCode issueCode)
    {
        if (depth > 3 || !visited.Add(offset) || offset < 0 || offset > bytes.Length - 16)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var namedCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset + 12, 2));
        var idCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset + 14, 2));
        var entryCount = checked(namedCount + idCount);
        var entriesOffset = checked(offset + 16);
        if (entriesOffset > bytes.Length - checked(entryCount * 8))
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        for (var index = 0; index < entryCount; index++)
        {
            var entryOffset = entriesOffset + (index * 8);
            var nameValue = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(entryOffset, 4));
            var dataValue = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(entryOffset + 4, 4));
            var identifier = (nameValue & 0x80000000) != 0
                ? ReadResourceName(bytes, checked((int)(nameValue & 0x7fffffff)), issueCode)
                : "#" + (nameValue & 0xffff).ToString(System.Globalization.CultureInfo.InvariantCulture);
            var nextPath = path.Append(identifier).ToArray();
            if ((dataValue & 0x80000000) != 0)
            {
                WalkResourceDirectory(
                    bytes,
                    checked((int)(dataValue & 0x7fffffff)),
                    depth + 1,
                    nextPath,
                    resourceRva,
                    reader,
                    maximumCount,
                    visited,
                    resources,
                    issueCode);
                continue;
            }

            if (resources.Count >= maximumCount || dataValue > bytes.Length - 16)
            {
                throw new PortableExecutableDirectoryException(
                    resources.Count >= maximumCount
                        ? PortableExecutableIssueCode.DirectoryLimitExceeded
                        : issueCode);
            }

            var dataOffset = checked((int)dataValue);
            var dataRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(dataOffset, 4));
            var size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(dataOffset + 4, 4));
            var codePage = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(dataOffset + 8, 4));
            if (size > 0)
            {
                var dataBlock = reader.GetSectionData(checked((int)dataRva));
                if (dataBlock.Length < size)
                {
                    throw new PortableExecutableDirectoryException(issueCode);
                }
            }

            resources.Add(new PortableExecutableResource(
                nextPath.ElementAtOrDefault(0) ?? "#0",
                nextPath.ElementAtOrDefault(1) ?? "#0",
                nextPath.ElementAtOrDefault(2) ?? "#0",
                dataRva,
                size,
                codePage));
        }
    }

    private static string ReadResourceName(
        byte[] bytes,
        int offset,
        PortableExecutableIssueCode issueCode)
    {
        if (offset < 0 || offset > bytes.Length - 2)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var length = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
        if (length is 0 or > MaximumResourceNameLength ||
            offset + 2 > bytes.Length - checked(length * 2))
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var value = Encoding.Unicode.GetString(bytes, offset + 2, length * 2);
        if (value.Any(char.IsControl))
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        return value;
    }

    private static string ReadAscii(
        PEReader reader,
        uint rva,
        int maximumLength,
        PortableExecutableIssueCode issueCode)
    {
        var block = reader.GetSectionData(checked((int)rva));
        var value = block.GetReader();
        var bytes = new List<byte>(Math.Min(maximumLength, value.RemainingBytes));
        while (value.RemainingBytes > 0 && bytes.Count < maximumLength)
        {
            var next = value.ReadByte();
            if (next == 0)
            {
                if (bytes.Count == 0 || bytes.Any(character => character is < 0x20 or > 0x7e))
                {
                    throw new PortableExecutableDirectoryException(issueCode);
                }

                return Encoding.ASCII.GetString(bytes.ToArray());
            }

            bytes.Add(next);
        }

        throw new PortableExecutableDirectoryException(issueCode);
    }

    private static BlobReader GetReader(
        PEReader reader,
        int rva,
        int length,
        PortableExecutableIssueCode issueCode)
    {
        if (rva <= 0 || length <= 0)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var block = reader.GetSectionData(rva);
        if (block.Length < length)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        return block.GetReader(0, length);
    }

    private static uint ReadUInt32(
        PEReader reader,
        uint rva,
        PortableExecutableIssueCode issueCode) =>
        GetReader(reader, checked((int)rva), 4, issueCode).ReadUInt32();

    private static ushort ReadUInt16(
        PEReader reader,
        uint rva,
        PortableExecutableIssueCode issueCode) =>
        GetReader(reader, checked((int)rva), 2, issueCode).ReadUInt16();

    private static uint NormalizeDelayPointer(
        uint value,
        uint attributes,
        ulong imageBase,
        PortableExecutableIssueCode issueCode)
    {
        if ((attributes & 1) != 0)
        {
            return value;
        }

        if (value < imageBase || value - imageBase > uint.MaxValue)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        return (uint)(value - imageBase);
    }

    private static bool IsEmpty(DirectoryEntry directory)
    {
        if (directory.RelativeVirtualAddress == 0 && directory.Size == 0)
        {
            return true;
        }

        if (directory.RelativeVirtualAddress <= 0 || directory.Size <= 0)
        {
            throw new PortableExecutableDirectoryException(
                PortableExecutableIssueCode.InvalidHeaders);
        }

        return false;
    }

    private static void ValidateDirectory(
        DirectoryEntry directory,
        int recordSize,
        int maximumRecords,
        PortableExecutableIssueCode issueCode)
    {
        if (directory.RelativeVirtualAddress <= 0 || directory.Size < recordSize ||
            directory.Size / recordSize > maximumRecords)
        {
            throw new PortableExecutableDirectoryException(
                directory.Size / recordSize > maximumRecords
                    ? PortableExecutableIssueCode.DirectoryLimitExceeded
                    : issueCode);
        }

        var block = directory.RelativeVirtualAddress;
        _ = checked(block + directory.Size);
    }
}

internal sealed class PortableExecutableDirectoryException : Exception
{
    public PortableExecutableDirectoryException(
        PortableExecutableIssueCode issueCode,
        Exception? innerException = null)
        : base("The PE data directory is invalid.", innerException)
    {
        IssueCode = issueCode;
    }

    public PortableExecutableIssueCode IssueCode { get; }
}
