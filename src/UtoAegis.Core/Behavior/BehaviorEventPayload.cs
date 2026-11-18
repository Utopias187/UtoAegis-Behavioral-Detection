namespace UtoAegis.Core.Behavior;

public abstract record BehaviorEventPayload;

public sealed record BehaviorArtifactIdentity
{
    public const int MaximumPathTokenLength = 1_024;

    public BehaviorArtifactIdentity(string? pathToken, string? sha256)
    {
        PathToken = ValidateOptionalText(pathToken, nameof(pathToken));
        if (sha256 is not null && !Reputation.MalwareHashIndicator.TryNormalizeSha256(sha256, out sha256))
        {
            throw new ArgumentException("SHA-256 identities must contain 64 hexadecimal characters.", nameof(sha256));
        }

        if (PathToken is null && sha256 is null)
        {
            throw new ArgumentException("An artifact identity requires a path token or SHA-256.");
        }

        Sha256 = sha256;
    }

    public string? PathToken { get; }

    public string? Sha256 { get; }

    private static string? ValidateOptionalText(string? value, string parameterName)
    {
        if (value is null)
        {
            return null;
        }

        if (value.Length is < 1 or > MaximumPathTokenLength || value.Any(char.IsControl))
        {
            throw new ArgumentException(
                $"Path tokens must contain 1 to {MaximumPathTokenLength} printable characters.",
                parameterName);
        }

        return value;
    }
}

public sealed record ProcessStartedPayload(
    BehaviorArtifactIdentity Executable,
    BehaviorIntegrityClass Integrity) : BehaviorEventPayload;

public sealed record ProcessStoppedPayload(int? ExitCode) : BehaviorEventPayload;

public sealed record ImageLoadedPayload(
    BehaviorArtifactIdentity Image,
    BehaviorSignatureState SignatureState) : BehaviorEventPayload;

public sealed record FileChangedPayload : BehaviorEventPayload
{
    public FileChangedPayload(string pathToken, BehaviorOperation operation)
    {
        Artifact = new BehaviorArtifactIdentity(pathToken, null);
        Operation = operation;
    }

    public BehaviorArtifactIdentity Artifact { get; }

    public BehaviorOperation Operation { get; }
}

public sealed record RegistryChangedPayload(
    BehaviorRegistryLocation Location,
    BehaviorOperation Operation) : BehaviorEventPayload;

public sealed record NetworkConnectedPayload : BehaviorEventPayload
{
    public NetworkConnectedPayload(
        BehaviorNetworkProtocol protocol,
        BehaviorNetworkDirection direction,
        BehaviorAddressScope addressScope,
        int destinationPort)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destinationPort, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(destinationPort, 65_535);
        Protocol = protocol;
        Direction = direction;
        AddressScope = addressScope;
        DestinationPort = destinationPort;
    }

    public BehaviorNetworkProtocol Protocol { get; }

    public BehaviorNetworkDirection Direction { get; }

    public BehaviorAddressScope AddressScope { get; }

    public int DestinationPort { get; }
}

public sealed record ProviderHealthPayload : BehaviorEventPayload
{
    public ProviderHealthPayload(
        BehaviorEventSource provider,
        BehaviorProviderState state,
        long droppedEventCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(droppedEventCount);
        Provider = provider;
        State = state;
        DroppedEventCount = droppedEventCount;
    }

    public BehaviorEventSource Provider { get; }

    public BehaviorProviderState State { get; }

    public long DroppedEventCount { get; }
}
