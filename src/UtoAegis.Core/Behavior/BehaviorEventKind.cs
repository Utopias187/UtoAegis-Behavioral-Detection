namespace UtoAegis.Core.Behavior;

public enum BehaviorEventKind
{
    ProcessStarted = 0,
    ProcessStopped = 1,
    ImageLoaded = 2,
    FileChanged = 3,
    RegistryChanged = 4,
    NetworkConnected = 5,
    ProviderHealth = 6
}

public enum BehaviorEventSource
{
    Process = 0,
    Image = 1,
    FileSystem = 2,
    Registry = 3,
    Network = 4,
    Collector = 5
}

public enum BehaviorProviderState
{
    Healthy = 0,
    Degraded = 1,
    Unreliable = 2,
    Stopped = 3
}

public enum BehaviorOperation
{
    Created = 0,
    Modified = 1,
    Deleted = 2,
    Renamed = 3
}

public enum BehaviorIntegrityClass
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4,
    Protected = 5
}

public enum BehaviorSignatureState
{
    Unknown = 0,
    NoSignature = 1,
    SignaturePresent = 2,
    Trusted = 3,
    Invalid = 4
}

public enum BehaviorNetworkProtocol
{
    Tcp = 0,
    Udp = 1
}

public enum BehaviorNetworkDirection
{
    Outbound = 0,
    Inbound = 1
}

public enum BehaviorAddressScope
{
    Loopback = 0,
    Private = 1,
    LinkLocal = 2,
    Public = 3,
    Unknown = 4
}

public enum BehaviorRegistryLocation
{
    Other = 0,
    RunKey = 1,
    Service = 2,
    Winlogon = 3,
    ScheduledTask = 4,
    SecurityPolicy = 5
}
