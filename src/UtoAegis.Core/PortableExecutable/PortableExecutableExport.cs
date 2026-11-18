namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableExport(
    string? Name,
    uint Ordinal,
    uint Rva,
    string? Forwarder);
