namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableDirectoryFacts(
    IReadOnlyList<PortableExecutableImport> Imports,
    IReadOnlyList<PortableExecutableImport> DelayImports,
    IReadOnlyList<PortableExecutableExport> Exports,
    IReadOnlyList<PortableExecutableResource> Resources)
{
    public static PortableExecutableDirectoryFacts Empty { get; } = new([], [], [], []);
}
