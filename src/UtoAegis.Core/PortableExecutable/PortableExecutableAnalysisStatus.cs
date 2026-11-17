namespace UtoAegis.Core.PortableExecutable;

public enum PortableExecutableAnalysisStatus
{
    Analyzed = 0,
    NotPortableExecutable = 1,
    Unsupported = 2,
    Malformed = 3,
    UnsafeInput = 4,
    IoError = 5
}
