using System.Buffers;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace UtoAegis.Core.PortableExecutable;

public sealed class PortableExecutableAnalyzer
{
    public const int MaximumDataDirectoryCount = 16;

    private readonly PortableExecutableAnalyzerOptions options;

    public PortableExecutableAnalyzer(PortableExecutableAnalyzerOptions? options = null)
    {
        this.options = options ?? new PortableExecutableAnalyzerOptions();
    }

    public async ValueTask<PortableExecutableAnalysisResult> AnalyzeAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        file.Refresh();
        if (!file.Exists || (file.Attributes & FileAttributes.Directory) != 0)
        {
            return Result(
                PortableExecutableAnalysisStatus.UnsafeInput,
                0,
                PortableExecutableIssueCode.NotRegularFile);
        }

        if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return Result(
                PortableExecutableAnalysisStatus.UnsafeInput,
                file.Length,
                PortableExecutableIssueCode.ReparsePoint);
        }

        if (file.Length == 0)
        {
            return Result(
                PortableExecutableAnalysisStatus.UnsafeInput,
                0,
                PortableExecutableIssueCode.EmptyFile);
        }

        if (file.Length > options.MaximumFileSizeBytes)
        {
            return Result(
                PortableExecutableAnalysisStatus.UnsafeInput,
                file.Length,
                PortableExecutableIssueCode.FileTooLarge);
        }

        try
        {
            await using var stream = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.RandomAccess);
            var openedLength = stream.Length;
            if (openedLength != file.Length || openedLength > options.MaximumFileSizeBytes)
            {
                return Result(
                    PortableExecutableAnalysisStatus.UnsafeInput,
                    openedLength,
                    PortableExecutableIssueCode.FileChanged);
            }

            var signature = new byte[2];
            var read = await stream.ReadAsync(signature, cancellationToken).ConfigureAwait(false);
            if (read != signature.Length || signature[0] != (byte)'M' || signature[1] != (byte)'Z')
            {
                return Result(
                    PortableExecutableAnalysisStatus.NotPortableExecutable,
                    openedLength,
                    PortableExecutableIssueCode.NotPortableExecutable);
            }

            if (openedLength < 64)
            {
                return Result(
                    PortableExecutableAnalysisStatus.Malformed,
                    openedLength,
                    PortableExecutableIssueCode.TruncatedHeaders);
            }

            stream.Position = 0;
            using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            var headers = reader.PEHeaders;
            var peHeader = headers.PEHeader;
            if (peHeader is null)
            {
                return Result(
                    PortableExecutableAnalysisStatus.Unsupported,
                    openedLength,
                    PortableExecutableIssueCode.UnsupportedFormat);
            }

            var format = peHeader.Magic switch
            {
                PEMagic.PE32 => PortableExecutableFormat.Pe32,
                PEMagic.PE32Plus => PortableExecutableFormat.Pe32Plus,
                _ => (PortableExecutableFormat?)null
            };
            if (format is null)
            {
                return Result(
                    PortableExecutableAnalysisStatus.Unsupported,
                    openedLength,
                    PortableExecutableIssueCode.UnsupportedFormat);
            }

            var sectionCount = headers.CoffHeader.NumberOfSections;
            if (sectionCount is < 1 || sectionCount > options.MaximumSectionCount)
            {
                return Result(
                    PortableExecutableAnalysisStatus.Malformed,
                    openedLength,
                    PortableExecutableIssueCode.ExcessiveSectionCount);
            }

            if (peHeader.NumberOfRvaAndSizes is < 0 or > MaximumDataDirectoryCount)
            {
                return Result(
                    PortableExecutableAnalysisStatus.Malformed,
                    openedLength,
                    PortableExecutableIssueCode.ExcessiveDataDirectoryCount);
            }

            if (peHeader.FileAlignment <= 0 || peHeader.SectionAlignment <= 0)
            {
                return Result(
                    PortableExecutableAnalysisStatus.Malformed,
                    openedLength,
                    PortableExecutableIssueCode.InvalidAlignment);
            }

            var header = new PortableExecutableHeader(
                format.Value,
                (ushort)headers.CoffHeader.Machine,
                unchecked((uint)headers.CoffHeader.TimeDateStamp),
                (ushort)headers.CoffHeader.Characteristics,
                (ushort)peHeader.Subsystem,
                (ushort)peHeader.DllCharacteristics,
                peHeader.ImageBase,
                ToUInt32(peHeader.AddressOfEntryPoint),
                ToUInt32(peHeader.SectionAlignment),
                ToUInt32(peHeader.FileAlignment),
                ToUInt32(peHeader.SizeOfImage),
                ToUInt32(peHeader.SizeOfHeaders),
                peHeader.CheckSum,
                sectionCount,
                peHeader.NumberOfRvaAndSizes);
            var sections = await ReadSectionsAsync(
                stream,
                headers.SectionHeaders,
                header,
                openedLength,
                cancellationToken).ConfigureAwait(false);
            if (sections.IssueCode != PortableExecutableIssueCode.None)
            {
                return Result(
                    PortableExecutableAnalysisStatus.Malformed,
                    openedLength,
                    sections.IssueCode);
            }

            if (stream.Length != openedLength)
            {
                return Result(
                    PortableExecutableAnalysisStatus.UnsafeInput,
                    stream.Length,
                    PortableExecutableIssueCode.FileChanged);
            }

            return new PortableExecutableAnalysisResult(
                PortableExecutableAnalysisStatus.Analyzed,
                openedLength,
                header,
                sections.Sections,
                PortableExecutableIssueCode.None);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (BadImageFormatException)
        {
            return Result(
                PortableExecutableAnalysisStatus.Malformed,
                file.Length,
                PortableExecutableIssueCode.InvalidHeaders);
        }
        catch (OverflowException)
        {
            return Result(
                PortableExecutableAnalysisStatus.Malformed,
                file.Length,
                PortableExecutableIssueCode.InvalidHeaders);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Result(
                PortableExecutableAnalysisStatus.IoError,
                file.Length,
                PortableExecutableIssueCode.IoFailure);
        }
    }

    private static uint ToUInt32(int value) => checked((uint)value);

    private static async ValueTask<SectionReadResult> ReadSectionsAsync(
        FileStream stream,
        IReadOnlyList<SectionHeader> sectionHeaders,
        PortableExecutableHeader header,
        long fileLength,
        CancellationToken cancellationToken)
    {
        var sections = new PortableExecutableSection[sectionHeaders.Count];
        var virtualEnds = new ulong[sectionHeaders.Count];
        var rawEnds = new ulong[sectionHeaders.Count];
        for (var index = 0; index < sectionHeaders.Count; index++)
        {
            var source = sectionHeaders[index];
            if (source.Name.Length > 8 || source.Name.Any(character => character is < ' ' or > '~'))
            {
                return SectionReadResult.Failed(PortableExecutableIssueCode.InvalidSectionName);
            }

            uint virtualAddress;
            uint virtualSize;
            uint rawOffset;
            uint rawSize;
            try
            {
                virtualAddress = ToUInt32(source.VirtualAddress);
                virtualSize = ToUInt32(source.VirtualSize);
                rawOffset = ToUInt32(source.PointerToRawData);
                rawSize = ToUInt32(source.SizeOfRawData);
            }
            catch (OverflowException)
            {
                return SectionReadResult.Failed(
                    PortableExecutableIssueCode.SectionRangeOutOfBounds);
            }

            var rawEnd = (ulong)rawOffset + rawSize;
            if (rawSize > 0 && (rawOffset == 0 || rawEnd > (ulong)fileLength))
            {
                return SectionReadResult.Failed(
                    PortableExecutableIssueCode.SectionRangeOutOfBounds);
            }

            var mappedSize = Math.Max(virtualSize, rawSize);
            var virtualEnd = (ulong)virtualAddress + mappedSize;
            if (mappedSize > 0 &&
                (virtualAddress == 0 || virtualEnd > header.SizeOfImage || virtualEnd > uint.MaxValue))
            {
                return SectionReadResult.Failed(
                    PortableExecutableIssueCode.VirtualRangeOutOfBounds);
            }

            var entropy = await CalculateEntropyAsync(
                stream,
                rawOffset,
                rawSize,
                cancellationToken).ConfigureAwait(false);
            rawEnds[index] = rawEnd;
            virtualEnds[index] = virtualEnd;
            sections[index] = new PortableExecutableSection(
                source.Name,
                virtualAddress,
                virtualSize,
                rawOffset,
                rawSize,
                (uint)source.SectionCharacteristics,
                entropy,
                rawSize == 0 || rawOffset % header.FileAlignment == 0,
                mappedSize == 0 || virtualAddress % header.SectionAlignment == 0,
                rawSize > 0 && rawOffset < header.SizeOfHeaders,
                false,
                false,
                mappedSize > 0 &&
                    header.EntryPointRva >= virtualAddress &&
                    header.EntryPointRva < virtualEnd);
        }

        for (var index = 0; index < sections.Length; index++)
        {
            var rawOverlap = false;
            var virtualOverlap = false;
            for (var other = 0; other < sections.Length; other++)
            {
                if (other == index)
                {
                    continue;
                }

                rawOverlap |= RangesOverlap(
                    sections[index].RawDataOffset,
                    rawEnds[index],
                    sections[other].RawDataOffset,
                    rawEnds[other]);
                virtualOverlap |= RangesOverlap(
                    sections[index].VirtualAddress,
                    virtualEnds[index],
                    sections[other].VirtualAddress,
                    virtualEnds[other]);
            }

            sections[index] = sections[index] with
            {
                RawRangeOverlapsAnotherSection = rawOverlap,
                VirtualRangeOverlapsAnotherSection = virtualOverlap
            };
        }

        return new SectionReadResult(sections, PortableExecutableIssueCode.None);
    }

    private static bool RangesOverlap(ulong firstStart, ulong firstEnd, ulong secondStart, ulong secondEnd) =>
        firstEnd > firstStart && secondEnd > secondStart &&
        firstStart < secondEnd && secondStart < firstEnd;

    private static async ValueTask<double> CalculateEntropyAsync(
        FileStream stream,
        uint offset,
        uint size,
        CancellationToken cancellationToken)
    {
        if (size == 0)
        {
            return 0;
        }

        stream.Position = offset;
        var counts = new long[256];
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            var remaining = (long)size;
            while (remaining > 0)
            {
                var requested = (int)Math.Min(buffer.Length, remaining);
                var read = await stream.ReadAsync(
                    buffer.AsMemory(0, requested),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new BadImageFormatException("The section data is truncated.");
                }

                for (var index = 0; index < read; index++)
                {
                    counts[buffer[index]]++;
                }

                remaining -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        var entropy = 0d;
        foreach (var count in counts)
        {
            if (count == 0)
            {
                continue;
            }

            var probability = count / (double)size;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static PortableExecutableAnalysisResult Result(
        PortableExecutableAnalysisStatus status,
        long fileSizeBytes,
        PortableExecutableIssueCode issueCode) =>
        new(status, fileSizeBytes, null, [], issueCode);

    private sealed record SectionReadResult(
        IReadOnlyList<PortableExecutableSection> Sections,
        PortableExecutableIssueCode IssueCode)
    {
        public static SectionReadResult Failed(PortableExecutableIssueCode issueCode) =>
            new([], issueCode);
    }
}
