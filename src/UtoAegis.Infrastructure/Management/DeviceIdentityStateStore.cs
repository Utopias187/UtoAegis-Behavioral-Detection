using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceIdentityStateStore
{
    private const int MaximumStateLength = 8 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 4,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly string statePath;

    public DeviceIdentityStateStore(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        this.statePath = Path.GetFullPath(statePath);
        var parent = Path.GetDirectoryName(this.statePath)!;
        if (Path.GetFullPath(parent) == Path.GetPathRoot(parent))
        {
            throw new ArgumentException(
                "The device identity state must not be stored at a filesystem root.",
                nameof(statePath));
        }
    }

    public async ValueTask<DeviceIdentityState> CreateOrLoadAsync(
        DeviceIdentityState proposed,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proposed);
        var parent = Path.GetDirectoryName(statePath)!;
        Directory.CreateDirectory(parent);
        var directory = new DirectoryInfo(parent);
        directory.Refresh();
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new DeviceManagementException(
                "The device identity state directory must not be a reparse point.");
        }

        await using var operationLock = await AcquireLockAsync(
            statePath + ".lock",
            cancellationToken).ConfigureAwait(false);
        var current = await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
        if (current is not null)
        {
            if (current != proposed)
            {
                throw new DeviceManagementException(
                    "The proposed device identity conflicts with the persisted identity.");
            }

            return current;
        }

        await WriteAsync(proposed, cancellationToken).ConfigureAwait(false);
        return proposed;
    }

    public ValueTask<DeviceIdentityState?> LoadAsync(
        CancellationToken cancellationToken = default) =>
        LoadCoreAsync(cancellationToken);

    private async ValueTask<DeviceIdentityState?> LoadCoreAsync(CancellationToken cancellationToken)
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
            throw new DeviceManagementException("The device identity state file is unsafe.");
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(statePath, cancellationToken).ConfigureAwait(false);
            if (bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble))
            {
                throw new DeviceManagementException(
                    "The device identity state must be UTF-8 without a byte-order mark.");
            }

            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            EnsureUniqueProperties(document.RootElement);
            var state = document.RootElement.Deserialize<StateDocument>(SerializerOptions) ??
                throw new DeviceManagementException("The device identity state is empty.");
            if (state.SchemaVersion != DeviceIdentityState.CurrentSchemaVersion ||
                state.CreatedUtc is null)
            {
                throw new DeviceManagementException(
                    "The device identity state has an unsupported schema or is incomplete.");
            }

            return new DeviceIdentityState(
                state.DeviceId!,
                state.KeyName!,
                state.PublicKeySha256!,
                state.CreatedUtc.Value);
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or
                ArgumentException or NotSupportedException)
        {
            throw new DeviceManagementException(
                "The device identity state could not be read.",
                exception);
        }
    }

    private async ValueTask WriteAsync(
        DeviceIdentityState state,
        CancellationToken cancellationToken)
    {
        var document = new StateDocument(
            state.SchemaVersion,
            state.DeviceId,
            state.KeyName,
            state.PublicKeySha256,
            state.CreatedUtc);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document, SerializerOptions);
        var temporaryPath = statePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllBytesAsync(temporaryPath, bytes, cancellationToken).ConfigureAwait(false);
            File.Move(temporaryPath, statePath, overwrite: false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException(
                "The device identity state could not be committed.",
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

    private static void EnsureUniqueProperties(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new DeviceManagementException(
                "The device identity state must contain a JSON object.");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                throw new DeviceManagementException(
                    $"Duplicate JSON property '{property.Name}' is not allowed.");
            }
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
        int SchemaVersion,
        string? DeviceId,
        string? KeyName,
        string? PublicKeySha256,
        DateTimeOffset? CreatedUtc);
}
