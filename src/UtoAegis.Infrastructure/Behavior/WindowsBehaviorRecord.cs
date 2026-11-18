using System.Net;
using UtoAegis.Core.Behavior;

namespace UtoAegis.Infrastructure.Behavior;

public abstract record WindowsBehaviorRecord(DateTimeOffset? SourceUtc);

public sealed record WindowsProcessStartedRecord(
    int ProcessId,
    long StartMarker,
    int? ParentProcessId,
    long? ParentStartMarker,
    string? ExecutablePath,
    string? Sha256,
    BehaviorIntegrityClass Integrity,
    DateTimeOffset? SourceUtc = null) : WindowsBehaviorRecord(SourceUtc);

public sealed record WindowsProcessStoppedRecord(
    int ProcessId,
    long StartMarker,
    int? ExitCode,
    DateTimeOffset? SourceUtc = null) : WindowsBehaviorRecord(SourceUtc);

public sealed record WindowsImageLoadedRecord(
    int ProcessId,
    long StartMarker,
    string ImagePath,
    string? Sha256,
    BehaviorSignatureState SignatureState,
    DateTimeOffset? SourceUtc = null) : WindowsBehaviorRecord(SourceUtc);

public sealed record WindowsFileChangedRecord(
    int ProcessId,
    long StartMarker,
    string Path,
    BehaviorOperation Operation,
    DateTimeOffset? SourceUtc = null) : WindowsBehaviorRecord(SourceUtc);

public sealed record WindowsRegistryChangedRecord(
    int ProcessId,
    long StartMarker,
    string KeyPath,
    BehaviorOperation Operation,
    DateTimeOffset? SourceUtc = null) : WindowsBehaviorRecord(SourceUtc);

public sealed record WindowsNetworkConnectedRecord(
    int ProcessId,
    long StartMarker,
    BehaviorNetworkProtocol Protocol,
    BehaviorNetworkDirection Direction,
    IPAddress RemoteAddress,
    int DestinationPort,
    DateTimeOffset? SourceUtc = null) : WindowsBehaviorRecord(SourceUtc);

public sealed record WindowsProviderHealthRecord(
    BehaviorEventSource Provider,
    BehaviorProviderState State,
    long DroppedEventCount,
    DateTimeOffset? SourceUtc = null) : WindowsBehaviorRecord(SourceUtc);
