namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableHeader(
    PortableExecutableFormat Format,
    ushort Machine,
    uint CoffTimestamp,
    ushort Characteristics,
    ushort Subsystem,
    ushort DllCharacteristics,
    ulong ImageBase,
    uint EntryPointRva,
    uint SectionAlignment,
    uint FileAlignment,
    uint SizeOfImage,
    uint SizeOfHeaders,
    uint Checksum,
    int SectionCount,
    int DataDirectoryCount);
