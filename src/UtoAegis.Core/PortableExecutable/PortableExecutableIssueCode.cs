namespace UtoAegis.Core.PortableExecutable;

public enum PortableExecutableIssueCode
{
    None = 0,
    NotPortableExecutable = 1,
    NotRegularFile = 2,
    ReparsePoint = 3,
    EmptyFile = 4,
    FileTooLarge = 5,
    TruncatedHeaders = 6,
    InvalidHeaders = 7,
    UnsupportedFormat = 8,
    ExcessiveSectionCount = 9,
    ExcessiveDataDirectoryCount = 10,
    InvalidSectionName = 11,
    SectionRangeOutOfBounds = 12,
    VirtualRangeOutOfBounds = 13,
    InvalidAlignment = 14,
    FileChanged = 15,
    IoFailure = 16
}
