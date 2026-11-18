using UtoAegis.Core.PortableExecutable;

namespace UtoAegis.Core.History;

public sealed record ScanHistoryPortableExecutable(
    PortableExecutableAnalysisStatus Status,
    PortableExecutableIssueCode IssueCode,
    PortableExecutableFormat? Format,
    ushort? Machine,
    int SectionCount,
    int ImportCount,
    int DelayImportCount,
    int ExportCount,
    int ResourceCount,
    bool IsManaged,
    int CertificateCount,
    long OverlaySize)
{
    public static ScanHistoryPortableExecutable FromResult(
        PortableExecutableAnalysisResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return new ScanHistoryPortableExecutable(
            result.Status,
            result.IssueCode,
            result.Header?.Format,
            result.Header?.Machine,
            result.Sections.Count,
            result.DirectoryFacts.Imports.Count,
            result.DirectoryFacts.DelayImports.Count,
            result.DirectoryFacts.Exports.Count,
            result.DirectoryFacts.Resources.Count,
            result.ImageFacts.ManagedMetadata is not null,
            result.ImageFacts.Certificates.Count,
            result.ImageFacts.Overlay.OverlaySize);
    }
}
