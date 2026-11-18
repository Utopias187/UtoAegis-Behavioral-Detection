using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using UtoAegis.Core.Behavior;

namespace UtoAegis.Infrastructure.Behavior;

public sealed class WindowsBehaviorNormalizer
{
    public const int MaximumTrackedProcessCount = 4_096;
    public const int MaximumProviderStringLength = 32_767;

    private readonly Guid collectorGenerationId;
    private readonly Dictionary<ProcessKey, TrackedProcess> processes = [];
    private long registrationOrder;

    public WindowsBehaviorNormalizer(Guid collectorGenerationId)
    {
        if (collectorGenerationId == Guid.Empty)
        {
            throw new ArgumentException("Collector generation IDs cannot be empty.", nameof(collectorGenerationId));
        }

        this.collectorGenerationId = collectorGenerationId;
    }

    public int TrackedProcessCount => processes.Count;

    public bool TryNormalize(WindowsBehaviorRecord record, out BehaviorEventDraft? draft)
    {
        ArgumentNullException.ThrowIfNull(record);
        try
        {
            draft = record switch
            {
                WindowsProcessStartedRecord started => NormalizeProcessStarted(started),
                WindowsProcessStoppedRecord stopped => NormalizeProcessStopped(stopped),
                WindowsImageLoadedRecord image => NormalizeImageLoaded(image),
                WindowsFileChangedRecord file => NormalizeFileChanged(file),
                WindowsRegistryChangedRecord registry => NormalizeRegistryChanged(registry),
                WindowsNetworkConnectedRecord network => NormalizeNetworkConnected(network),
                WindowsProviderHealthRecord health => NormalizeProviderHealth(health),
                _ => null
            };
            return draft is not null;
        }
        catch (Exception exception) when (
            exception is ArgumentException or
            CryptographicException or
            EncoderFallbackException)
        {
            draft = null;
            return false;
        }
    }

    public static string CreatePathToken(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path.Length > MaximumProviderStringLength || path.Any(char.IsControl))
        {
            throw new ArgumentException("Windows provider paths are invalid or overlong.", nameof(path));
        }

        var normalized = path.Trim().Replace('/', '\\').ToUpperInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return $"path-sha256:{Convert.ToHexStringLower(hash)}";
    }

    public static BehaviorAddressScope ClassifyAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (IPAddress.IsLoopback(address))
        {
            return BehaviorAddressScope.Loopback;
        }

        if (address.IsIPv6LinkLocal || IsIpv4Range(address, 169, 254))
        {
            return BehaviorAddressScope.LinkLocal;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork &&
            (IsIpv4Range(address, 10) ||
             IsIpv4Range(address, 192, 168) ||
             IsIpv4Range(address, 172, secondMinimum: 16, secondMaximum: 31)) ||
            address.AddressFamily == AddressFamily.InterNetworkV6 &&
            address.GetAddressBytes()[0] is >= 0xfc and <= 0xfd)
        {
            return BehaviorAddressScope.Private;
        }

        return address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6
            ? BehaviorAddressScope.Public
            : BehaviorAddressScope.Unknown;
    }

    public static BehaviorRegistryLocation ClassifyRegistryLocation(string keyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);
        if (keyPath.Length > MaximumProviderStringLength || keyPath.Any(char.IsControl))
        {
            throw new ArgumentException("Windows registry provider paths are invalid or overlong.", nameof(keyPath));
        }

        var normalized = keyPath.Replace('/', '\\').ToUpperInvariant();
        if (normalized.Contains("\\CURRENTVERSION\\RUN", StringComparison.Ordinal) ||
            normalized.Contains("\\CURRENTVERSION\\RUNONCE", StringComparison.Ordinal))
        {
            return BehaviorRegistryLocation.RunKey;
        }

        if (normalized.Contains("\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\", StringComparison.Ordinal))
        {
            return BehaviorRegistryLocation.Service;
        }

        if (normalized.Contains("\\WINLOGON", StringComparison.Ordinal))
        {
            return BehaviorRegistryLocation.Winlogon;
        }

        if (normalized.Contains("\\SCHEDULE\\TASKCACHE\\", StringComparison.Ordinal))
        {
            return BehaviorRegistryLocation.ScheduledTask;
        }

        if (normalized.Contains("\\POLICIES\\", StringComparison.Ordinal))
        {
            return BehaviorRegistryLocation.SecurityPolicy;
        }

        return BehaviorRegistryLocation.Other;
    }

    private BehaviorEventDraft NormalizeProcessStarted(WindowsProcessStartedRecord record)
    {
        var subject = Register(record.ProcessId, record.StartMarker);
        BehaviorProcessInstance? parent = null;
        if (record.ParentProcessId is { } parentId && record.ParentStartMarker is { } parentMarker)
        {
            parent = Resolve(parentId, parentMarker);
        }

        var identity = CreateArtifact(record.ExecutablePath, record.Sha256, "path-unavailable");
        return new BehaviorEventDraft(
            record.SourceUtc,
            BehaviorEventSource.Process,
            BehaviorEventKind.ProcessStarted,
            subject,
            parent,
            new ProcessStartedPayload(identity, record.Integrity));
    }

    private BehaviorEventDraft? NormalizeProcessStopped(WindowsProcessStoppedRecord record)
    {
        var subject = Resolve(record.ProcessId, record.StartMarker);
        if (subject is null)
        {
            return null;
        }

        processes.Remove(new ProcessKey(record.ProcessId, record.StartMarker));
        return new BehaviorEventDraft(
            record.SourceUtc,
            BehaviorEventSource.Process,
            BehaviorEventKind.ProcessStopped,
            subject,
            null,
            new ProcessStoppedPayload(record.ExitCode));
    }

    private BehaviorEventDraft? NormalizeImageLoaded(WindowsImageLoadedRecord record)
    {
        var subject = Resolve(record.ProcessId, record.StartMarker);
        return subject is null
            ? null
            : new BehaviorEventDraft(
                record.SourceUtc,
                BehaviorEventSource.Image,
                BehaviorEventKind.ImageLoaded,
                subject,
                null,
                new ImageLoadedPayload(
                    CreateArtifact(record.ImagePath, record.Sha256, "path-unavailable"),
                    record.SignatureState));
    }

    private BehaviorEventDraft? NormalizeFileChanged(WindowsFileChangedRecord record)
    {
        var subject = Resolve(record.ProcessId, record.StartMarker);
        return subject is null
            ? null
            : new BehaviorEventDraft(
                record.SourceUtc,
                BehaviorEventSource.FileSystem,
                BehaviorEventKind.FileChanged,
                subject,
                null,
                new FileChangedPayload(CreatePathToken(record.Path), record.Operation));
    }

    private BehaviorEventDraft? NormalizeRegistryChanged(WindowsRegistryChangedRecord record)
    {
        var subject = Resolve(record.ProcessId, record.StartMarker);
        return subject is null
            ? null
            : new BehaviorEventDraft(
                record.SourceUtc,
                BehaviorEventSource.Registry,
                BehaviorEventKind.RegistryChanged,
                subject,
                null,
                new RegistryChangedPayload(
                    ClassifyRegistryLocation(record.KeyPath),
                    record.Operation));
    }

    private BehaviorEventDraft? NormalizeNetworkConnected(WindowsNetworkConnectedRecord record)
    {
        var subject = Resolve(record.ProcessId, record.StartMarker);
        return subject is null
            ? null
            : new BehaviorEventDraft(
                record.SourceUtc,
                BehaviorEventSource.Network,
                BehaviorEventKind.NetworkConnected,
                subject,
                null,
                new NetworkConnectedPayload(
                    record.Protocol,
                    record.Direction,
                    ClassifyAddress(record.RemoteAddress),
                    record.DestinationPort));
    }

    private static BehaviorEventDraft NormalizeProviderHealth(WindowsProviderHealthRecord record) => new(
        record.SourceUtc,
        BehaviorEventSource.Collector,
        BehaviorEventKind.ProviderHealth,
        null,
        null,
        new ProviderHealthPayload(record.Provider, record.State, record.DroppedEventCount));

    private BehaviorProcessInstance Register(int processId, long startMarker)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(processId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(startMarker);
        var key = new ProcessKey(processId, startMarker);
        if (processes.TryGetValue(key, out var existing))
        {
            return existing.Instance;
        }

        if (processes.Count == MaximumTrackedProcessCount)
        {
            var oldest = processes.MinBy(pair => pair.Value.RegistrationOrder).Key;
            processes.Remove(oldest);
        }

        var instance = new BehaviorProcessInstance(collectorGenerationId, processId, startMarker);
        processes.Add(key, new TrackedProcess(instance, checked(++registrationOrder)));
        return instance;
    }

    private BehaviorProcessInstance? Resolve(int processId, long startMarker) =>
        processes.TryGetValue(new ProcessKey(processId, startMarker), out var process)
            ? process.Instance
            : null;

    private static BehaviorArtifactIdentity CreateArtifact(
        string? path,
        string? sha256,
        string fallbackToken) =>
        new(path is null ? fallbackToken : CreatePathToken(path), sha256);

    private static bool IsIpv4Range(
        IPAddress address,
        byte first,
        byte? second = null,
        byte? secondMinimum = null,
        byte? secondMaximum = null)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == first &&
            (second is null || bytes[1] == second) &&
            (secondMinimum is null || bytes[1] >= secondMinimum) &&
            (secondMaximum is null || bytes[1] <= secondMaximum);
    }

    private readonly record struct ProcessKey(int ProcessId, long StartMarker);

    private sealed record TrackedProcess(
        BehaviorProcessInstance Instance,
        long RegistrationOrder);
}
