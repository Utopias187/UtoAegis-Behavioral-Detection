namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableAnalysisResult(
    PortableExecutableAnalysisStatus Status,
    long FileSizeBytes,
    PortableExecutableHeader? Header,
    PortableExecutableIssueCode IssueCode)
{
    public bool IsPortableExecutable => Status == PortableExecutableAnalysisStatus.Analyzed;
}
