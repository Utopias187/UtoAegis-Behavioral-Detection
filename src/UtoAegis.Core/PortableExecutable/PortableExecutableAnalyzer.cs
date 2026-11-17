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

    private static PortableExecutableAnalysisResult Result(
        PortableExecutableAnalysisStatus status,
        long fileSizeBytes,
        PortableExecutableIssueCode issueCode) =>
        new(status, fileSizeBytes, null, issueCode);
}
