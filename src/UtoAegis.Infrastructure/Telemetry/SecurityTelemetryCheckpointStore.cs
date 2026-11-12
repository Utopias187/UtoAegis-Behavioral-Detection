using System.Text.Json;

namespace UtoAegis.Infrastructure.Telemetry;

public sealed class SecurityTelemetryCheckpointStore : IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions =
        new(JsonSerializerDefaults.Web);

    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public SecurityTelemetryCheckpointStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public async ValueTask<SecurityTelemetryCheckpoint> LoadAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask SaveAsync(
        SecurityTelemetryCheckpoint checkpoint,
        CancellationToken cancellationToken = default)
    {
        Validate(checkpoint);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
            if (checkpoint.Sequence < current.Sequence ||
                (checkpoint.Sequence == current.Sequence &&
                 !string.Equals(checkpoint.Hash, current.Hash, StringComparison.Ordinal)))
            {
                throw new SecurityTelemetryException(
                    "The telemetry delivery checkpoint cannot move backward or change at the same sequence.");
            }

            if (checkpoint == current)
            {
                return;
            }

            var bytes = JsonSerializer.SerializeToUtf8Bytes(checkpoint, SerializerOptions);
            await AtomicWriteAsync(_path, bytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    private async ValueTask<SecurityTelemetryCheckpoint> LoadCoreAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return SecurityTelemetryCheckpoint.Empty;
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(_path, cancellationToken).ConfigureAwait(false);
            var checkpoint = JsonSerializer.Deserialize<SecurityTelemetryCheckpoint>(
                bytes,
                SerializerOptions) ?? throw new SecurityTelemetryException(
                    "The telemetry checkpoint is empty.");
            Validate(checkpoint);
            return checkpoint;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or
                ArgumentException)
        {
            throw new SecurityTelemetryException(
                "The telemetry delivery checkpoint is invalid or unavailable.",
                exception);
        }
    }

    internal static async ValueTask AtomicWriteAsync(
        string path,
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void Validate(SecurityTelemetryCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (checkpoint.Sequence < 0 ||
            checkpoint.Hash.Length != 64 ||
            checkpoint.Hash.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("The telemetry checkpoint is invalid.", nameof(checkpoint));
        }
    }
}
