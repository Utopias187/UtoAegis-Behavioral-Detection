namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableSection(
    string Name,
    uint VirtualAddress,
    uint VirtualSize,
    uint RawDataOffset,
    uint RawDataSize,
    uint Characteristics,
    double Entropy,
    bool IsRawRangeAligned,
    bool IsVirtualAddressAligned,
    bool RawRangeOverlapsHeaders,
    bool RawRangeOverlapsAnotherSection,
    bool VirtualRangeOverlapsAnotherSection,
    bool ContainsEntryPoint);
