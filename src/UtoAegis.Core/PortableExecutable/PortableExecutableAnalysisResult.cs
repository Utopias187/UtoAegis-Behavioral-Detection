namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableAnalysisResult(
    PortableExecutableAnalysisStatus Status,
    long FileSizeBytes,
    PortableExecutableHeader? Header,
    IReadOnlyList<PortableExecutableSection> Sections,
    PortableExecutableDirectoryFacts DirectoryFacts,
    PortableExecutableIssueCode IssueCode)
{
    public bool IsPortableExecutable => Status == PortableExecutableAnalysisStatus.Analyzed;
}
