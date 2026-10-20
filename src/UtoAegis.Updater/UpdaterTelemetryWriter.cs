using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UtoAegis.Updater;

public sealed class UpdaterTelemetryWriter : IDisposable
{
    private static readonly byte[] NewLine = "\n"u8.ToArray();
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private readonly string _path;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public UpdaterTelemetryWriter(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public async ValueTask WriteAsync(
        UpdaterTelemetryRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(record, SerializerOptions);
        if (bytes.Length > 16 * 1024)
        {
            throw new IOException("The updater telemetry record exceeds its size limit.");
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var stream = new FileStream(
                _path,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,
                bufferSize: 16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(NewLine, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public void Dispose() => _writeLock.Dispose();
}
