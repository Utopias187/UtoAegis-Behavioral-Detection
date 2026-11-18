namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableResource(
    string Type,
    string Name,
    string Language,
    uint DataRva,
    uint Size,
    uint CodePage);
