namespace UtoAegis.Core.PortableExecutable;

public sealed record PortableExecutableImageFacts(
    PortableExecutableManagedMetadata? ManagedMetadata,
    IReadOnlyList<PortableExecutableCertificate> Certificates,
    PortableExecutableOverlayFacts Overlay)
{
    public static PortableExecutableImageFacts Empty { get; } = new(
        null,
        [],
        new PortableExecutableOverlayFacts(0, 0, 0, 0));
}

public sealed record PortableExecutableManagedMetadata(
    string MetadataVersion,
    uint CorFlags,
    uint EntryPointTokenOrRva,
    uint MetadataRva,
    uint MetadataSize,
    uint ResourcesRva,
    uint ResourcesSize,
    uint StrongNameSignatureRva,
    uint StrongNameSignatureSize,
    string ModuleName,
    string? AssemblyName,
    string? AssemblyVersion,
    string? AssemblyCulture,
    int TypeDefinitionCount,
    int MethodDefinitionCount,
    int AssemblyReferenceCount);

public sealed record PortableExecutableCertificate(
    long FileOffset,
    uint Length,
    ushort Revision,
    ushort CertificateType);

public sealed record PortableExecutableOverlayFacts(
    long FirstTrailingByteOffset,
    long TrailingDataSize,
    long CertificateBytesExcluded,
    long OverlaySize);
