using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace UtoAegis.Core.PortableExecutable;

internal static class PortableExecutableImageReader
{
    private const int MaximumMetadataStringLength = 512;

    public static async ValueTask<PortableExecutableImageFacts> ReadAsync(
        FileStream stream,
        PEReader reader,
        PEHeader header,
        IReadOnlyList<PortableExecutableSection> sections,
        long fileLength,
        PortableExecutableAnalyzerOptions options,
        CancellationToken cancellationToken)
    {
        var metadata = ReadManagedMetadata(reader, options);
        var mappedEnd = Math.Max(
            checked((ulong)header.SizeOfHeaders),
            sections.Max(section => checked((ulong)section.RawDataOffset + section.RawDataSize)));
        if (mappedEnd > (ulong)fileLength)
        {
            throw new PortableExecutableDirectoryException(
                PortableExecutableIssueCode.SectionRangeOutOfBounds);
        }

        var certificates = await ReadCertificatesAsync(
            stream,
            header.CertificateTableDirectory,
            checked((long)mappedEnd),
            fileLength,
            options,
            cancellationToken).ConfigureAwait(false);
        var trailingSize = fileLength - checked((long)mappedEnd);
        var certificateBytes = certificates.Count == 0
            ? 0
            : header.CertificateTableDirectory.Size;
        if (certificateBytes > trailingSize)
        {
            throw new PortableExecutableDirectoryException(
                PortableExecutableIssueCode.InvalidCertificateTable);
        }

        return new PortableExecutableImageFacts(
            metadata,
            certificates,
            new PortableExecutableOverlayFacts(
                checked((long)mappedEnd),
                trailingSize,
                certificateBytes,
                trailingSize - certificateBytes));
    }

    private static PortableExecutableManagedMetadata? ReadManagedMetadata(
        PEReader reader,
        PortableExecutableAnalyzerOptions options)
    {
        if (!reader.HasMetadata)
        {
            return null;
        }

        try
        {
            var corHeader = reader.PEHeaders.CorHeader ?? throw new BadImageFormatException();
            var metadata = reader.GetMetadataReader(MetadataReaderOptions.None);
            var totalRows = checked(
                metadata.TypeDefinitions.Count +
                metadata.MethodDefinitions.Count +
                metadata.AssemblyReferences.Count);
            if (totalRows > options.MaximumMetadataTableRowCount)
            {
                throw new PortableExecutableDirectoryException(
                    PortableExecutableIssueCode.DirectoryLimitExceeded);
            }

            var module = metadata.GetModuleDefinition();
            var moduleName = ReadString(metadata, module.Name);
            string? assemblyName = null;
            string? assemblyVersion = null;
            string? assemblyCulture = null;
            if (metadata.IsAssembly)
            {
                var assembly = metadata.GetAssemblyDefinition();
                assemblyName = ReadString(metadata, assembly.Name);
                assemblyVersion = assembly.Version.ToString();
                if (!assembly.Culture.IsNil)
                {
                    assemblyCulture = ReadString(metadata, assembly.Culture);
                }
            }

            return new PortableExecutableManagedMetadata(
                ValidateString(metadata.MetadataVersion),
                (uint)corHeader.Flags,
                checked((uint)corHeader.EntryPointTokenOrRelativeVirtualAddress),
                checked((uint)corHeader.MetadataDirectory.RelativeVirtualAddress),
                checked((uint)corHeader.MetadataDirectory.Size),
                checked((uint)corHeader.ResourcesDirectory.RelativeVirtualAddress),
                checked((uint)corHeader.ResourcesDirectory.Size),
                checked((uint)corHeader.StrongNameSignatureDirectory.RelativeVirtualAddress),
                checked((uint)corHeader.StrongNameSignatureDirectory.Size),
                moduleName,
                assemblyName,
                assemblyVersion,
                assemblyCulture,
                metadata.TypeDefinitions.Count,
                metadata.MethodDefinitions.Count,
                metadata.AssemblyReferences.Count);
        }
        catch (PortableExecutableDirectoryException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentOutOfRangeException or
                OverflowException)
        {
            throw new PortableExecutableDirectoryException(
                PortableExecutableIssueCode.InvalidManagedMetadata,
                exception);
        }
    }

    private static async ValueTask<IReadOnlyList<PortableExecutableCertificate>> ReadCertificatesAsync(
        FileStream stream,
        DirectoryEntry directory,
        long mappedEnd,
        long fileLength,
        PortableExecutableAnalyzerOptions options,
        CancellationToken cancellationToken)
    {
        if (directory.RelativeVirtualAddress == 0 && directory.Size == 0)
        {
            return [];
        }

        var issueCode = PortableExecutableIssueCode.InvalidCertificateTable;
        var tableOffset = directory.RelativeVirtualAddress;
        var tableSize = directory.Size;
        if (tableOffset <= 0 || tableSize < 8 || tableSize > options.MaximumCertificateTableSize ||
            (tableOffset & 7) != 0 || (long)tableOffset + tableSize > fileLength ||
            tableOffset < mappedEnd)
        {
            throw new PortableExecutableDirectoryException(issueCode);
        }

        var certificates = new List<PortableExecutableCertificate>();
        var header = new byte[8];
        var consumed = 0;
        while (consumed < tableSize)
        {
            if (certificates.Count >= options.MaximumCertificateCount || consumed > tableSize - 8)
            {
                throw new PortableExecutableDirectoryException(
                    certificates.Count >= options.MaximumCertificateCount
                        ? PortableExecutableIssueCode.DirectoryLimitExceeded
                        : issueCode);
            }

            stream.Position = checked(tableOffset + consumed);
            await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0, 4));
            if (length < 8 || length > tableSize - consumed)
            {
                throw new PortableExecutableDirectoryException(issueCode);
            }

            certificates.Add(new PortableExecutableCertificate(
                checked(tableOffset + consumed),
                length,
                BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(4, 2)),
                BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(6, 2))));
            var alignedLength = checked((int)((length + 7u) & ~7u));
            if (alignedLength > tableSize - consumed)
            {
                throw new PortableExecutableDirectoryException(issueCode);
            }

            consumed += alignedLength;
        }

        return certificates;
    }

    private static string ReadString(MetadataReader reader, StringHandle handle) =>
        ValidateString(reader.GetString(handle));

    private static string ValidateString(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaximumMetadataStringLength ||
            value.Any(char.IsControl))
        {
            throw new BadImageFormatException();
        }

        return value;
    }
}
