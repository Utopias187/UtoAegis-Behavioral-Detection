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

    public async ValueTask<DeviceIdentityState> RetireAsync(
        string expectedDeviceId,
        string archivePath,
        CancellationToken cancellationToken = default)
    {
        expectedDeviceId = NormalizeDeviceId(expectedDeviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        var fullArchivePath = Path.GetFullPath(archivePath);
        if (string.Equals(fullArchivePath, statePath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetPathRoot(fullArchivePath),
                Path.GetPathRoot(statePath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The identity archive must be a different path on the same volume.",
                nameof(archivePath));
        }

        var archiveParent = Path.GetDirectoryName(fullArchivePath)!;
        if (Path.GetFullPath(archiveParent) == Path.GetPathRoot(archiveParent))
        {
            throw new ArgumentException(
                "The identity archive must not be stored at a filesystem root.",
                nameof(archivePath));
        }

        Directory.CreateDirectory(archiveParent);
        var archiveDirectory = new DirectoryInfo(archiveParent);
        archiveDirectory.Refresh();
        if (archiveDirectory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new DeviceManagementException(
                "The identity archive directory must not be a reparse point.");
        }

        await using var operationLock = await AcquireLockAsync(
            statePath + ".lock",
            cancellationToken).ConfigureAwait(false);
        var current = await LoadCoreAsync(cancellationToken).ConfigureAwait(false) ??
            throw new DeviceManagementException("No device identity state is available to retire.");
        if (!string.Equals(current.DeviceId, expectedDeviceId, StringComparison.Ordinal))
        {
            throw new DeviceManagementException(
                "The expected device ID does not match the persisted identity.");
        }

        if (File.Exists(fullArchivePath))
        {
            throw new DeviceManagementException("The identity archive path already exists.");
        }

        try
        {
            File.Move(statePath, fullArchivePath, overwrite: false);
            return current;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException(
                "The device identity state could not be archived atomically.",
                exception);
        }
    }

    public async ValueTask RestoreRetiredAsync(
        string archivePath,
        string expectedDeviceId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        expectedDeviceId = NormalizeDeviceId(expectedDeviceId);
        var fullArchivePath = Path.GetFullPath(archivePath);
        var archived = await new DeviceIdentityStateStore(fullArchivePath)
            .LoadAsync(cancellationToken).ConfigureAwait(false) ??
            throw new DeviceManagementException("The retired identity archive is missing.");
        if (!string.Equals(archived.DeviceId, expectedDeviceId, StringComparison.Ordinal))
        {
            throw new DeviceManagementException(
                "The retired identity archive belongs to a different device.");
        }

        await using var operationLock = await AcquireLockAsync(
            statePath + ".lock",
            cancellationToken).ConfigureAwait(false);
        if (File.Exists(statePath))
        {
            throw new DeviceManagementException(
                "Active identity state already exists and cannot be replaced by an archive.");
        }

        try
        {
            File.Move(fullArchivePath, statePath, overwrite: false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException(
                "The retired device identity could not be restored atomically.",
                exception);
        }
    }

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

    private static string NormalizeDeviceId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length != 32 || value.Any(character =>
                !char.IsAsciiDigit(character) &&
                character is not (>= 'a' and <= 'f') and not (>= 'A' and <= 'F')))
        {
            throw new ArgumentException(
                "The expected device ID must contain exactly 32 hexadecimal characters.",
                nameof(value));
        }

        return value.ToLowerInvariant();
    }

    private sealed record StateDocument(
        int SchemaVersion,
        string? DeviceId,
        string? KeyName,
        string? PublicKeySha256,
        DateTimeOffset? CreatedUtc);
}
