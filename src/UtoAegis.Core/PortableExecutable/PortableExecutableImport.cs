namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableImport(
    string ModuleName,
    string? SymbolName,
    ushort? Ordinal,
    ushort? Hint,
    bool IsDelayLoaded);
