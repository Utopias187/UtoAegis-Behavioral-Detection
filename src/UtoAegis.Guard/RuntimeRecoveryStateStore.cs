using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Guard;

internal sealed class RuntimeRecoveryStateStore : IRuntimeRecoveryLimiter
{
    private const int MaximumStateLength = 64 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 5,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly string statePath;
    private readonly TimeProvider timeProvider;

    public RuntimeRecoveryStateStore(string statePath, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        this.statePath = Path.GetFullPath(statePath);
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<bool> TryReserveAsync(
        RuntimePolicyManifest policy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.MaximumRecoveriesPerWindow == 0)
        {
            return false;
        }

        var parent = Path.GetDirectoryName(statePath)!;
        Directory.CreateDirectory(parent);
        var parentInfo = new DirectoryInfo(parent);
        parentInfo.Refresh();
        if (parentInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException(
                "The integrity recovery state directory must not be a reparse point.");
        }

        await using var operationLock = await AcquireLockAsync(
            statePath + ".lock",
            cancellationToken).ConfigureAwait(false);
        var current = await ReadAsync(cancellationToken).ConfigureAwait(false);
        var now = timeProvider.GetUtcNow();
        var cutoff = now - policy.RecoveryWindow;
        var attempts = current is not null &&
            current.Sequence == policy.Sequence &&
            string.Equals(current.PolicyId, policy.PolicyId, StringComparison.Ordinal)
                ? current.Attempts.Where(attempt => attempt > cutoff && attempt <= now).ToList()
                : [];
        if (attempts.Count >= policy.MaximumRecoveriesPerWindow)
        {
            return false;
        }

        attempts.Add(now);
        var updated = new StateDocument(policy.PolicyId, policy.Sequence, attempts);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(updated, SerializerOptions);
        var temporaryPath = statePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllBytesAsync(temporaryPath, bytes, cancellationToken)
                .ConfigureAwait(false);
            File.Move(temporaryPath, statePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        return true;
    }

    private async ValueTask<StateDocument?> ReadAsync(CancellationToken cancellationToken)
    {
        var file = new FileInfo(statePath);
        file.Refresh();
        if (!file.Exists)
        {
            return null;
        }

        if (file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            file.Length is <= 0 or > MaximumStateLength)
        {
            throw new InvalidOperationException("The integrity recovery state is unsafe.");
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(statePath, cancellationToken)
                .ConfigureAwait(false);
            var state = JsonSerializer.Deserialize<StateDocument>(bytes, SerializerOptions) ??
                throw new InvalidOperationException("The integrity recovery state is empty.");
            if (state.Sequence <= 0 || string.IsNullOrWhiteSpace(state.PolicyId) ||
                state.Attempts is null || state.Attempts.Count > 100)
            {
                throw new InvalidOperationException("The integrity recovery state is invalid.");
            }

            return state;
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                "The integrity recovery state is not valid JSON.",
                exception);
        }
    }

    private static async ValueTask<FileStream> AcquireLockAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(50, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private sealed record StateDocument(
        string PolicyId,
        long Sequence,
        IReadOnlyList<DateTimeOffset> Attempts);
}
