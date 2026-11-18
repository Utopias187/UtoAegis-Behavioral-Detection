using System.Buffers.Binary;
using System.Reflection.PortableExecutable;

namespace UtoAegis.Core.PortableExecutable;

internal static class PortableExecutablePlatformReader
{
    private const int MaximumDirectorySize = 16 * 1024 * 1024;
    private const ushort MachineArm = 0x01c4;
    private const ushort MachineAmd64 = 0x8664;
    private const ushort MachineArm64 = 0xaa64;
    private const ushort MachineIa64 = 0x0200;

    public static PortableExecutablePlatformFacts Read(
        PEReader reader,
        PEHeader header,
        ushort machine,
        long fileLength,
        PortableExecutableAnalyzerOptions options)
    {
        var debug = ReadDebug(reader, header.DebugTableDirectory, fileLength, options);
        var tls = ReadTls(reader, header, options);
        var loadConfiguration = ReadLoadConfiguration(reader, header);
        var relocations = ReadRelocations(reader, header.BaseRelocationTableDirectory, options);
        var exceptions = ReadExceptions(
            reader,
            header.ExceptionTableDirectory,
            machine,
            options);
        return new PortableExecutablePlatformFacts(
            debug,
            tls,
            loadConfiguration,
            relocations,
            exceptions);
    }

    private static PortableExecutableDebugEntry[] ReadDebug(
        PEReader reader,
        DirectoryEntry directory,
        long fileLength,
        PortableExecutableAnalyzerOptions options)
    {
        if (IsEmpty(directory, PortableExecutableIssueCode.InvalidDebugDirectory))
        {
            return [];
        }

        ValidateDirectory(
            directory,
            28,
            options.MaximumDebugEntryCount,
            PortableExecutableIssueCode.InvalidDebugDirectory);
        if (directory.Size % 28 != 0)
        {
            throw new PortableExecutableDirectoryException(
                PortableExecutableIssueCode.InvalidDebugDirectory);
        }

        var entries = new PortableExecutableDebugEntry[directory.Size / 28];
        for (var index = 0; index < entries.Length; index++)
        {
            var data = GetBytes(
                reader,
                checked(directory.RelativeVirtualAddress + (index * 28)),
                28,
                PortableExecutableIssueCode.InvalidDebugDirectory);
            var size = ReadUInt32(data, 16);
            var dataRva = ReadUInt32(data, 20);
            var fileOffset = ReadUInt32(data, 24);
            if (size > 0)
            {
                if ((ulong)fileOffset + size > (ulong)fileLength)
                {
                    throw new PortableExecutableDirectoryException(
                        PortableExecutableIssueCode.InvalidDebugDirectory);
                }

                if (dataRva != 0)
                {
                    _ = GetBytes(
                        reader,
                        checked((int)dataRva),
                        checked((int)size),
                        PortableExecutableIssueCode.InvalidDebugDirectory);
                }
            }

            entries[index] = new PortableExecutableDebugEntry(
                ReadUInt32(data, 0),
                ReadUInt32(data, 4),
                ReadUInt16(data, 8),
                ReadUInt16(data, 10),
                ReadUInt32(data, 12),
                size,
                dataRva,
                fileOffset);
        }

        return entries;
    }

    private static PortableExecutableTlsFacts? ReadTls(
        PEReader reader,
        PEHeader header,
        PortableExecutableAnalyzerOptions options)
    {
        var directory = header.ThreadLocalStorageTableDirectory;
        var issueCode = PortableExecutableIssueCode.InvalidTlsDirectory;
        if (IsEmpty(directory, issueCode))
        {
            return null;
        }

        var isPe32Plus = header.Magic == PEMagic.PE32Plus;
        var size = isPe32Plus ? 40 : 24;
        ValidateDirectory(directory, size, 1, issueCode);
        var data = GetBytes(reader, directory.RelativeVirtualAddress, size, issueCode);
        var rawDataStart = ReadAddress(data, 0, isPe32Plus);
        var rawDataEnd = ReadAddress(data, isPe32Plus ? 8 : 4, isPe32Plus);
        var index = ReadAddress(data, isPe32Plus ? 16 : 8, isPe32Plus);
        var callbacks = ReadAddress(data, isPe32Plus ? 24 : 12, isPe32Plus);
        var rawDataStartRva = NormalizeVa(rawDataStart, header.ImageBase, issueCode);
        var rawDataEndRva = NormalizeVa(rawDataEnd, header.ImageBase, issueCode);
        if ((rawDataStartRva == 0) != (rawDataEndRva == 0) ||
            rawDataEndRva < rawDataStartRva)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var callbackTableRva = NormalizeVa(callbacks, header.ImageBase, issueCode);
        var callbackRvas = ReadTlsCallbacks(
            reader,
            callbackTableRva,
            header.ImageBase,
            isPe32Plus,
            options.MaximumTlsCallbackCount,
            issueCode);
        return new PortableExecutableTlsFacts(
            rawDataStartRva,
            rawDataEndRva,
            NormalizeVa(index, header.ImageBase, issueCode),
            callbackTableRva,
            ReadUInt32(data, isPe32Plus ? 32 : 16),
            ReadUInt32(data, isPe32Plus ? 36 : 20),
            callbackRvas);
    }

    private static uint[] ReadTlsCallbacks(
        PEReader reader,
        uint tableRva,
        ulong imageBase,
        bool isPe32Plus,
        int maximumCount,
        PortableExecutableIssueCode issueCode)
    {
        if (tableRva == 0)
        {
            return [];
        }

        var width = isPe32Plus ? 8 : 4;
        var block = reader.GetSectionData(checked((int)tableRva));
        var data = block.GetContent().AsSpan();
        var callbacks = new List<uint>();
        for (var offset = 0; offset <= data.Length - width; offset += width)
        {
            var value = isPe32Plus
                ? BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, width))
                : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, width));
            if (value == 0)
            {
                return callbacks.ToArray();
            }

            if (callbacks.Count >= maximumCount)
            {
                throw new PortableExecutableDirectoryException(
                    PortableExecutableIssueCode.DirectoryLimitExceeded);
            }

            callbacks.Add(NormalizeVa(value, imageBase, issueCode));
        }

        throw new PortableExecutableDirectoryException(issueCode);
    }

    private static PortableExecutableLoadConfiguration? ReadLoadConfiguration(
        PEReader reader,
        PEHeader header)
    {
        var directory = header.LoadConfigTableDirectory;
        var issueCode = PortableExecutableIssueCode.InvalidLoadConfiguration;
        if (IsEmpty(directory, issueCode))
        {
            return null;
        }

        if (directory.Size is < 24 or > MaximumDirectorySize)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var data = GetBytes(reader, directory.RelativeVirtualAddress, directory.Size, issueCode);
        var declaredSize = ReadUInt32(data, 0);
        if (declaredSize < 24 || declaredSize > directory.Size)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var available = data[..checked((int)declaredSize)];
        var isPe32Plus = header.Magic == PEMagic.PE32Plus;
        var cookieOffset = isPe32Plus ? 80 : 60;
        var handlerCountOffset = isPe32Plus ? 96 : 68;
        var guardFlagsOffset = isPe32Plus ? 136 : 88;
        var cookie = ReadOptionalAddress(available, cookieOffset, isPe32Plus);
        return new PortableExecutableLoadConfiguration(
            declaredSize,
            ReadUInt32(available, 4),
            ReadUInt16(available, 8),
            ReadUInt16(available, 10),
            ReadUInt32(available, 12),
            ReadUInt32(available, 16),
            ReadUInt32(available, 20),
            cookie is null ? null : NormalizeVa(cookie.Value, header.ImageBase, issueCode),
            ReadOptionalAddress(available, handlerCountOffset, isPe32Plus),
            available.Length >= guardFlagsOffset + 4
                ? ReadUInt32(available, guardFlagsOffset)
                : null);
    }

    private static PortableExecutableRelocation[] ReadRelocations(
        PEReader reader,
        DirectoryEntry directory,
        PortableExecutableAnalyzerOptions options)
    {
        var issueCode = PortableExecutableIssueCode.InvalidRelocationTable;
        if (IsEmpty(directory, issueCode))
        {
            return [];
        }

        if (directory.Size is < 8 or > MaximumDirectorySize)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var data = GetBytes(reader, directory.RelativeVirtualAddress, directory.Size, issueCode);
        var relocations = new List<PortableExecutableRelocation>();
        var offset = 0;
        while (offset < data.Length)
        {
            if (offset > data.Length - 8)
            {
                throw new PortableExecutableDirectoryException(issueCode);
            }

            var pageRva = ReadUInt32(data, offset);
            var blockSize = ReadUInt32(data, offset + 4);
            if (blockSize < 8 || (blockSize & 1) != 0 || blockSize > data.Length - offset)
            {
                throw new PortableExecutableDirectoryException(issueCode);
            }

            var blockEnd = checked(offset + (int)blockSize);
            for (var entryOffset = offset + 8; entryOffset < blockEnd; entryOffset += 2)
            {
                if (relocations.Count >= options.MaximumRelocationCount)
                {
                    throw new PortableExecutableDirectoryException(
                        PortableExecutableIssueCode.DirectoryLimitExceeded);
                }

                var value = ReadUInt16(data, entryOffset);
                relocations.Add(new PortableExecutableRelocation(
                    pageRva,
                    (ushort)(value >> 12),
                    (ushort)(value & 0x0fff)));
            }

            offset = blockEnd;
        }

        return relocations.ToArray();
    }

    private static PortableExecutableExceptionFacts? ReadExceptions(
        PEReader reader,
        DirectoryEntry directory,
        ushort machine,
        PortableExecutableAnalyzerOptions options)
    {
        var issueCode = PortableExecutableIssueCode.InvalidExceptionTable;
        if (IsEmpty(directory, issueCode))
        {
            return null;
        }

        if (directory.Size <= 0 || directory.Size > MaximumDirectorySize)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var entrySize = machine switch
        {
            MachineAmd64 or MachineIa64 => 12,
            MachineArm or MachineArm64 => 8,
            _ => 0
        };
        if (entrySize == 0)
        {
            _ = GetBytes(reader, directory.RelativeVirtualAddress, directory.Size, issueCode);
            return new PortableExecutableExceptionFacts(
                checked((uint)directory.RelativeVirtualAddress),
                checked((uint)directory.Size),
                0,
                0,
                []);
        }

        ValidateDirectory(directory, entrySize, options.MaximumExceptionEntryCount, issueCode);
        if (directory.Size % entrySize != 0)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var data = GetBytes(reader, directory.RelativeVirtualAddress, directory.Size, issueCode);
        var entries = new PortableExecutableExceptionEntry[directory.Size / entrySize];
        for (var index = 0; index < entries.Length; index++)
        {
            var offset = index * entrySize;
            entries[index] = new PortableExecutableExceptionEntry(
                ReadUInt32(data, offset),
                entrySize == 12 ? ReadUInt32(data, offset + 4) : null,
                ReadUInt32(data, offset + entrySize - 4));
        }

        return new PortableExecutableExceptionFacts(
            checked((uint)directory.RelativeVirtualAddress),
            checked((uint)directory.Size),
            entrySize,
            entries.Length,
            entries);
    }

    private static byte[] GetBytes(
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

        return block.GetContent(0, length).ToArray();
    }

    private static void ValidateDirectory(
        DirectoryEntry directory,
        int recordSize,
        int maximumRecords,
        PortableExecutableIssueCode issueCode)
    {
        if (directory.RelativeVirtualAddress <= 0 || directory.Size < recordSize)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        if (directory.Size > MaximumDirectorySize || directory.Size / recordSize > maximumRecords)
        {
            throw new PortableExecutableDirectoryException(
                PortableExecutableIssueCode.DirectoryLimitExceeded);
        }

        _ = checked(directory.RelativeVirtualAddress + directory.Size);
    }

    private static bool IsEmpty(
        DirectoryEntry directory,
        PortableExecutableIssueCode issueCode)
    {
        if (directory.RelativeVirtualAddress == 0 && directory.Size == 0)
        {
            return true;
        }

        if (directory.RelativeVirtualAddress <= 0 || directory.Size <= 0)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        return false;
    }

    private static ulong ReadAddress(ReadOnlySpan<byte> data, int offset, bool isPe32Plus) =>
        isPe32Plus
            ? BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8))
            : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));

    private static ulong? ReadOptionalAddress(
        ReadOnlySpan<byte> data,
        int offset,
        bool isPe32Plus)
    {
        var width = isPe32Plus ? 8 : 4;
        return data.Length >= offset + width ? ReadAddress(data, offset, isPe32Plus) : null;
    }

    private static uint NormalizeVa(
        ulong value,
        ulong imageBase,
        PortableExecutableIssueCode issueCode)
    {
        if (value == 0)
        {
            return 0;
        }

        if (value < imageBase || value - imageBase > uint.MaxValue)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        return (uint)(value - imageBase);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
}
