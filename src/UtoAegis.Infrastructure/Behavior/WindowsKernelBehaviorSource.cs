using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using UtoAegis.Core.Behavior;

namespace UtoAegis.Infrastructure.Behavior;

public sealed class WindowsKernelBehaviorSource
{
    public const int MinimumQueueCapacity = 2;
    public const int MaximumQueueCapacity = 8_192;

    private static readonly BehaviorEventSource[] ProviderSources =
    [
        BehaviorEventSource.Process,
        BehaviorEventSource.Image,
        BehaviorEventSource.FileSystem,
        BehaviorEventSource.Registry,
        BehaviorEventSource.Network
    ];

    private readonly int queueCapacity;
    private readonly TimeProvider timeProvider;

    public WindowsKernelBehaviorSource(int queueCapacity, TimeProvider? timeProvider = null)
    {
        if (queueCapacity is < MinimumQueueCapacity or > MaximumQueueCapacity)
        {
            throw new ArgumentOutOfRangeException(nameof(queueCapacity));
        }

        this.queueCapacity = queueCapacity;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async IAsyncEnumerable<WindowsBehaviorRecord> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows kernel telemetry requires Windows.");
        }

        var channel = Channel.CreateBounded<WindowsBehaviorRecord>(new BoundedChannelOptions(queueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true,
            AllowSynchronousContinuations = false
        });
        var processTable = new ProcessTable();
        var publisher = new BoundedPublisher(channel.Writer, timeProvider);
        var sessionName = $"UtoAegis-Behavior-{Environment.ProcessId}-{Guid.NewGuid():N}";
        using var session = new TraceEventSession(sessionName)
        {
            StopOnDispose = true
        };

        RegisterCallbacks(session, processTable, publisher);
        SeedRunningProcesses(processTable, publisher);
        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.ImageLoad |
            KernelTraceEventParser.Keywords.FileIOInit |
            KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.Registry |
            KernelTraceEventParser.Keywords.NetworkTCPIP);

        foreach (var provider in ProviderSources)
        {
            publisher.TryPublish(new WindowsProviderHealthRecord(
                provider,
                BehaviorProviderState.Healthy,
                0,
                timeProvider.GetUtcNow()));
        }

        using var registration = cancellationToken.Register(() => session.Stop(noThrow: true));
        var pump = Task.Run(() =>
        {
            try
            {
                session.Source.Process();
                channel.Writer.TryComplete();
            }
            catch (Exception exception)
            {
                channel.Writer.TryComplete(exception);
            }
        }, CancellationToken.None);

        try
        {
            await foreach (var record in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                yield return record;
            }
        }
        finally
        {
            session.Stop(noThrow: true);
            await pump.ConfigureAwait(false);
        }
    }

    private static void RegisterCallbacks(
        TraceEventSession session,
        ProcessTable processTable,
        BoundedPublisher publisher)
    {
        session.Source.Kernel.ProcessStart += data =>
        {
            if (!TryGetProcessId(data.ProcessID, out var processId))
            {
                return;
            }

            var startMarker = ToStartMarker(data.TimeStamp);
            processTable.Register(processId, startMarker);
            var parentMarker = processTable.TryGet(data.ParentID, out var resolvedParent)
                ? resolvedParent
                : (long?)null;
            publisher.TryPublish(new WindowsProcessStartedRecord(
                processId,
                startMarker,
                data.ParentID > 0 ? data.ParentID : null,
                parentMarker,
                NullIfWhiteSpace(data.ImageFileName),
                null,
                BehaviorIntegrityClass.Unknown,
                ToUtc(data.TimeStamp)));
        };
        session.Source.Kernel.ProcessStop += data =>
        {
            if (TryGetProcessId(data.ProcessID, out var processId) &&
                processTable.Remove(processId, out var startMarker))
            {
                publisher.TryPublish(new WindowsProcessStoppedRecord(
                    processId,
                    startMarker,
                    data.ExitStatus,
                    ToUtc(data.TimeStamp)));
            }
        };
        session.Source.Kernel.ImageLoad += data => PublishImage(data, processTable, publisher);
        session.Source.Kernel.FileIOWrite += data => PublishFile(
            data.ProcessID,
            data.FileName,
            BehaviorOperation.Modified,
            data.TimeStamp,
            processTable,
            publisher);
        session.Source.Kernel.FileIODelete += data => PublishFile(
            data.ProcessID,
            data.FileName,
            BehaviorOperation.Deleted,
            data.TimeStamp,
            processTable,
            publisher);
        session.Source.Kernel.FileIORename += data => PublishFile(
            data.ProcessID,
            data.FileName,
            BehaviorOperation.Renamed,
            data.TimeStamp,
            processTable,
            publisher);
        session.Source.Kernel.RegistryCreate += data => PublishRegistry(
            data,
            BehaviorOperation.Created,
            processTable,
            publisher);
        session.Source.Kernel.RegistrySetValue += data => PublishRegistry(
            data,
            BehaviorOperation.Modified,
            processTable,
            publisher);
        session.Source.Kernel.RegistrySetInformation += data => PublishRegistry(
            data,
            BehaviorOperation.Modified,
            processTable,
            publisher);
        session.Source.Kernel.RegistryDelete += data => PublishRegistry(
            data,
            BehaviorOperation.Deleted,
            processTable,
            publisher);
        session.Source.Kernel.RegistryDeleteValue += data => PublishRegistry(
            data,
            BehaviorOperation.Deleted,
            processTable,
            publisher);
        session.Source.Kernel.TcpIpConnect += data => PublishNetwork(
            data.ProcessID,
            data.daddr,
            data.dport,
            data.TimeStamp,
            processTable,
            publisher);
        session.Source.Kernel.TcpIpConnectIPV6 += data => PublishNetwork(
            data.ProcessID,
            data.daddr,
            data.dport,
            data.TimeStamp,
            processTable,
            publisher);
        session.Source.Kernel.LostEvent += data => publisher.ReportProviderLoss(ToUtc(data.TimeStamp));
    }

    private static void PublishImage(
        ImageLoadTraceData data,
        ProcessTable processTable,
        BoundedPublisher publisher)
    {
        if (processTable.TryGet(data.ProcessID, out var startMarker) &&
            NullIfWhiteSpace(data.FileName) is { } path)
        {
            publisher.TryPublish(new WindowsImageLoadedRecord(
                data.ProcessID,
                startMarker,
                path,
                null,
                BehaviorSignatureState.Unknown,
                ToUtc(data.TimeStamp)));
        }
    }

    private static void PublishFile(
        int processId,
        string? path,
        BehaviorOperation operation,
        DateTime timestamp,
        ProcessTable processTable,
        BoundedPublisher publisher)
    {
        if (processTable.TryGet(processId, out var startMarker) &&
            NullIfWhiteSpace(path) is { } normalizedPath)
        {
            publisher.TryPublish(new WindowsFileChangedRecord(
                processId,
                startMarker,
                normalizedPath,
                operation,
                ToUtc(timestamp)));
        }
    }

    private static void PublishRegistry(
        RegistryTraceData data,
        BehaviorOperation operation,
        ProcessTable processTable,
        BoundedPublisher publisher)
    {
        if (processTable.TryGet(data.ProcessID, out var startMarker) &&
            NullIfWhiteSpace(data.KeyName) is { } keyPath)
        {
            publisher.TryPublish(new WindowsRegistryChangedRecord(
                data.ProcessID,
                startMarker,
                keyPath,
                operation,
                ToUtc(data.TimeStamp)));
        }
    }

    private static void PublishNetwork(
        int processId,
        System.Net.IPAddress? address,
        int port,
        DateTime timestamp,
        ProcessTable processTable,
        BoundedPublisher publisher)
    {
        if (address is not null && port is >= 0 and <= ushort.MaxValue &&
            processTable.TryGet(processId, out var startMarker))
        {
            publisher.TryPublish(new WindowsNetworkConnectedRecord(
                processId,
                startMarker,
                BehaviorNetworkProtocol.Tcp,
                BehaviorNetworkDirection.Outbound,
                address,
                port,
                ToUtc(timestamp)));
        }
    }

    private static void SeedRunningProcesses(ProcessTable processTable, BoundedPublisher publisher)
    {
        foreach (var process in Process.GetProcesses().OrderBy(item => item.Id))
        {
            using (process)
            {
                try
                {
                    var processId = process.Id;
                    var startTime = process.StartTime.ToUniversalTime();
                    var startMarker = startTime.Ticks;
                    processTable.Register(processId, startMarker);
                    string? executablePath = null;
                    try
                    {
                        executablePath = process.MainModule?.FileName;
                    }
                    catch (Exception exception) when (
                        exception is InvalidOperationException or NotSupportedException or
                            System.ComponentModel.Win32Exception)
                    {
                    }

                    publisher.TryPublish(new WindowsProcessStartedRecord(
                        processId,
                        startMarker,
                        null,
                        null,
                        executablePath,
                        null,
                        BehaviorIntegrityClass.Unknown,
                        new DateTimeOffset(startTime)));
                }
                catch (Exception exception) when (
                    exception is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                }
            }
        }
    }

    private static bool TryGetProcessId(int candidate, out int processId)
    {
        processId = candidate;
        return candidate > 0;
    }

    private static long ToStartMarker(DateTime timestamp) => timestamp.ToUniversalTime().Ticks;

    private static DateTimeOffset ToUtc(DateTime timestamp) =>
        new(timestamp.ToUniversalTime());

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;

    internal sealed class ProcessTable
    {
        private readonly Dictionary<int, ProcessEntry> starts = [];
        private long registrationOrder;

        public int Count => starts.Count;

        public void Register(int processId, long startMarker)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(processId);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(startMarker);
            if (!starts.ContainsKey(processId) &&
                starts.Count == WindowsBehaviorNormalizer.MaximumTrackedProcessCount)
            {
                var oldest = starts.MinBy(item => item.Value.RegistrationOrder).Key;
                starts.Remove(oldest);
            }

            starts[processId] = new ProcessEntry(startMarker, checked(++registrationOrder));
        }

        public bool TryGet(int processId, out long startMarker)
        {
            if (starts.TryGetValue(processId, out var entry))
            {
                startMarker = entry.StartMarker;
                return true;
            }

            startMarker = 0;
            return false;
        }

        public bool Remove(int processId, out long startMarker)
        {
            if (!starts.Remove(processId, out var entry))
            {
                startMarker = 0;
                return false;
            }

            startMarker = entry.StartMarker;
            return true;
        }

        private sealed record ProcessEntry(long StartMarker, long RegistrationOrder);
    }

    private sealed class BoundedPublisher(
        ChannelWriter<WindowsBehaviorRecord> writer,
        TimeProvider timeProvider)
    {
        private long droppedEventCount;
        private long reportedDroppedEventCount;

        public void TryPublish(WindowsBehaviorRecord record)
        {
            PublishPendingLoss();
            if (!writer.TryWrite(record))
            {
                IncrementDroppedCount();
            }
        }

        public void ReportProviderLoss(DateTimeOffset sourceUtc)
        {
            IncrementDroppedCount();
            var dropped = Volatile.Read(ref droppedEventCount);
            if (writer.TryWrite(new WindowsProviderHealthRecord(
                    BehaviorEventSource.Collector,
                    BehaviorProviderState.Degraded,
                    dropped,
                    sourceUtc)))
            {
                Volatile.Write(ref reportedDroppedEventCount, dropped);
            }
        }

        private void PublishPendingLoss()
        {
            var dropped = Volatile.Read(ref droppedEventCount);
            if (dropped == Volatile.Read(ref reportedDroppedEventCount))
            {
                return;
            }

            if (writer.TryWrite(new WindowsProviderHealthRecord(
                    BehaviorEventSource.Collector,
                    BehaviorProviderState.Degraded,
                    dropped,
                    timeProvider.GetUtcNow())))
            {
                Volatile.Write(ref reportedDroppedEventCount, dropped);
            }
        }

        private void IncrementDroppedCount()
        {
            while (true)
            {
                var current = Volatile.Read(ref droppedEventCount);
                if (current == long.MaxValue ||
                    Interlocked.CompareExchange(ref droppedEventCount, current + 1, current) == current)
                {
                    return;
                }
            }
        }
    }
}
