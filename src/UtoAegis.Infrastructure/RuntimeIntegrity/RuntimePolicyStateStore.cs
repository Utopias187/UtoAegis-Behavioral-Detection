using System.Text.Json;
using System.Text.Json.Serialization;

namespace UtoAegis.Infrastructure.RuntimeIntegrity;

public sealed class RuntimePolicyStateStore
{
    private const int MaximumStateLength = 4 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 4,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly string statePath;

    public RuntimePolicyStateStore(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        this.statePath = Path.GetFullPath(statePath);
        var parent = Path.GetDirectoryName(this.statePath)!;
        if (Path.GetFullPath(parent) == Path.GetPathRoot(parent))
        {
            throw new ArgumentException(
                "The runtime policy state must not be stored at a filesystem root.",
                nameof(statePath));
        }
    }

    public async ValueTask AcceptAsync(
        VerifiedRuntimePolicy policy,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var parent = Path.GetDirectoryName(statePath)!;
        Directory.CreateDirectory(parent);
        var directory = new DirectoryInfo(parent);
        directory.Refresh();
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new RuntimePolicyException(
                "The runtime policy state directory must not be a reparse point.");
        }

        var lockPath = statePath + ".lock";
        await using var operationLock = await AcquireLockAsync(lockPath, cancellationToken)
            .ConfigureAwait(false);
        var current = await ReadAsync(cancellationToken).ConfigureAwait(false);
        if (current is not null)
        {
            if (policy.Manifest.Sequence < current.Sequence)
            {
                throw new RuntimePolicyException(
                    "The runtime policy sequence is lower than the anti-rollback floor.");
            }

            if (policy.Manifest.Sequence == current.Sequence)
            {
                if (!string.Equals(
                        policy.ManifestSha256,
                        current.ManifestSha256,
                        StringComparison.Ordinal))
                {
                    throw new RuntimePolicyException(
                        "The runtime policy changed without increasing its sequence.");
                }

                return;
            }
        }

        var state = new StateDocument(policy.Manifest.Sequence, policy.ManifestSha256);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state, SerializerOptions);
        var temporaryPath = statePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllBytesAsync(temporaryPath, bytes, cancellationToken)
                .ConfigureAwait(false);
            File.Move(temporaryPath, statePath, overwrite: true);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            throw new RuntimePolicyException(
                "The runtime policy anti-rollback state could not be committed.",
                exception);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
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
            throw new RuntimePolicyException("The runtime policy anti-rollback state is unsafe.");
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(statePath, cancellationToken)
                .ConfigureAwait(false);
            var state = JsonSerializer.Deserialize<StateDocument>(bytes, SerializerOptions) ??
                throw new RuntimePolicyException("The runtime policy anti-rollback state is empty.");
            if (state.Sequence <= 0 ||
                state.ManifestSha256.Length != 64 ||
                state.ManifestSha256.Any(character => !Uri.IsHexDigit(character)))
            {
                throw new RuntimePolicyException("The runtime policy anti-rollback state is invalid.");
            }

            return state;
        }
        catch (RuntimePolicyException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new RuntimePolicyException(
                "The runtime policy anti-rollback state could not be read.",
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

    private sealed record StateDocument(long Sequence, string ManifestSha256);
}
