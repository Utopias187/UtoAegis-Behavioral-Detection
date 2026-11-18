namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutablePlatformFacts(
    IReadOnlyList<PortableExecutableDebugEntry> DebugEntries,
    PortableExecutableTlsFacts? Tls,
    PortableExecutableLoadConfiguration? LoadConfiguration,
    IReadOnlyList<PortableExecutableRelocation> Relocations,
    PortableExecutableExceptionFacts? Exceptions)
{
    public static PortableExecutablePlatformFacts Empty { get; } =
        new([], null, null, [], null);
}

public sealed record PortableExecutableDebugEntry(
    uint Characteristics,
    uint Timestamp,
    ushort MajorVersion,
    ushort MinorVersion,
    uint Type,
    uint DataSize,
    uint DataRva,
    uint FileOffset);

public sealed record PortableExecutableTlsFacts(
    uint RawDataStartRva,
    uint RawDataEndRva,
    uint IndexRva,
    uint CallbackTableRva,
    uint ZeroFillSize,
    uint Characteristics,
    IReadOnlyList<uint> CallbackRvas);

public sealed record PortableExecutableLoadConfiguration(
    uint Size,
    uint Timestamp,
    ushort MajorVersion,
    ushort MinorVersion,
    uint GlobalFlagsClear,
    uint GlobalFlagsSet,
    uint CriticalSectionDefaultTimeout,
    uint? SecurityCookieRva,
    ulong? SeHandlerCount,
    uint? GuardFlags);

public sealed record PortableExecutableRelocation(
    uint PageRva,
    ushort Type,
    ushort Offset);

public sealed record PortableExecutableExceptionFacts(
    uint DirectoryRva,
    uint DirectorySize,
    int EntrySize,
    int DeclaredEntryCount,
    IReadOnlyList<PortableExecutableExceptionEntry> Entries);

public sealed record PortableExecutableExceptionEntry(
    uint BeginRva,
    uint? EndRva,
    uint UnwindData);
