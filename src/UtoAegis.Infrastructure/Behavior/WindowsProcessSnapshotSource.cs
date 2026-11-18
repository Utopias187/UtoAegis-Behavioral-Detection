using System.Diagnostics;
using System.Runtime.CompilerServices;
using UtoAegis.Core.Behavior;

namespace UtoAegis.Infrastructure.Behavior;

public sealed class WindowsProcessSnapshotSource
{
    public static readonly TimeSpan MinimumPollInterval = TimeSpan.FromMilliseconds(250);
    public static readonly TimeSpan MaximumPollInterval = TimeSpan.FromMinutes(1);

    private readonly TimeSpan pollInterval;
    private readonly TimeProvider timeProvider;

    public WindowsProcessSnapshotSource(TimeSpan pollInterval, TimeProvider? timeProvider = null)
    {
        if (pollInterval < MinimumPollInterval || pollInterval > MaximumPollInterval)
        {
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        }

        this.pollInterval = pollInterval;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async IAsyncEnumerable<WindowsBehaviorRecord> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows process telemetry requires Windows.");
        }

        var previous = new Dictionary<ProcessKey, ProcessSnapshot>();
        while (!cancellationToken.IsCancellationRequested)
        {
            var current = Capture();
            foreach (var snapshot in current.Values
                         .Where(item => !previous.ContainsKey(item.Key))
                         .OrderBy(item => item.ProcessId)
                         .ThenBy(item => item.StartMarker))
            {
                yield return new WindowsProcessStartedRecord(
                    snapshot.ProcessId,
                    snapshot.StartMarker,
                    null,
                    null,
                    snapshot.ExecutablePath,
                    null,
                    BehaviorIntegrityClass.Unknown,
                    timeProvider.GetUtcNow());
                if (snapshot.ExecutablePath is not null)
                {
                    yield return new WindowsImageLoadedRecord(
                        snapshot.ProcessId,
                        snapshot.StartMarker,
                        snapshot.ExecutablePath,
                        null,
                        BehaviorSignatureState.Unknown,
                        timeProvider.GetUtcNow());
                }
            }

            foreach (var snapshot in previous.Values
                         .Where(item => !current.ContainsKey(item.Key))
                         .OrderBy(item => item.ProcessId)
                         .ThenBy(item => item.StartMarker))
            {
                yield return new WindowsProcessStoppedRecord(
                    snapshot.ProcessId,
                    snapshot.StartMarker,
                    null,
                    timeProvider.GetUtcNow());
            }

            previous = current;
            await Task.Delay(pollInterval, timeProvider, cancellationToken).ConfigureAwait(false);
        }
    }

    internal static IReadOnlyList<WindowsBehaviorRecord> CompareSnapshots(
        IReadOnlyCollection<ProcessSnapshot> previous,
        IReadOnlyCollection<ProcessSnapshot> current,
        DateTimeOffset observedUtc)
    {
        var oldKeys = previous.Select(item => item.Key).ToHashSet();
        var newKeys = current.Select(item => item.Key).ToHashSet();
        var records = new List<WindowsBehaviorRecord>();
        records.AddRange(current.Where(item => !oldKeys.Contains(item.Key))
            .OrderBy(item => item.ProcessId)
            .Select(item => (WindowsBehaviorRecord)new WindowsProcessStartedRecord(
                item.ProcessId,
                item.StartMarker,
                null,
                null,
                item.ExecutablePath,
                null,
                BehaviorIntegrityClass.Unknown,
                observedUtc)));
        records.AddRange(previous.Where(item => !newKeys.Contains(item.Key))
            .OrderBy(item => item.ProcessId)
            .Select(item => (WindowsBehaviorRecord)new WindowsProcessStoppedRecord(
                item.ProcessId,
                item.StartMarker,
                null,
                observedUtc)));
        return records;
    }

    private static Dictionary<ProcessKey, ProcessSnapshot> Capture()
    {
        var snapshots = new Dictionary<ProcessKey, ProcessSnapshot>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var id = process.Id;
                    var startMarker = process.StartTime.ToUniversalTime().Ticks;
                    string? path = null;
                    try
                    {
                        path = process.MainModule?.FileName;
                    }
                    catch (Exception exception) when (
                        exception is InvalidOperationException or NotSupportedException or
                            System.ComponentModel.Win32Exception)
                    {
                    }

                    var snapshot = new ProcessSnapshot(id, startMarker, path);
                    snapshots.TryAdd(snapshot.Key, snapshot);
                }
                catch (Exception exception) when (
                    exception is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                }
            }
        }

        return snapshots;
    }

    internal readonly record struct ProcessKey(int ProcessId, long StartMarker);

    internal sealed record ProcessSnapshot(int ProcessId, long StartMarker, string? ExecutablePath)
    {
        public ProcessKey Key => new(ProcessId, StartMarker);
    }
}
