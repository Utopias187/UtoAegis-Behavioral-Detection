using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceEnrollmentStateStore
{
    private const int MaximumStateLength = 16 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 4,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly string statePath;

    public DeviceEnrollmentStateStore(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        this.statePath = Path.GetFullPath(statePath);
        var parent = Path.GetDirectoryName(this.statePath)!;
        if (Path.GetFullPath(parent) == Path.GetPathRoot(parent))
        {
            throw new ArgumentException(
                "The enrollment state must not be stored at a filesystem root.",
                nameof(statePath));
        }
    }

    public async ValueTask<DeviceEnrollmentStateSnapshot> AcceptAsync(
        VerifiedDeviceEnrollmentCredential verified,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var parent = Path.GetDirectoryName(statePath)!;
        Directory.CreateDirectory(parent);
        var directory = new DirectoryInfo(parent);
        directory.Refresh();
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new DeviceManagementException(
                "The enrollment state directory must not be a reparse point.");
        }

        await using var operationLock = await AcquireLockAsync(
            statePath + ".lock",
            cancellationToken).ConfigureAwait(false);
        var current = await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
        var next = CreateSnapshot(verified);
        if (current is not null)
        {
            ValidateTransition(current, next);
            if (current.CredentialSequence == next.CredentialSequence)
            {
                return current;
            }
        }

        await WriteAsync(next, cancellationToken).ConfigureAwait(false);
        return next;
    }

    public ValueTask<DeviceEnrollmentStateSnapshot?> LoadAsync(
        CancellationToken cancellationToken = default) =>
        LoadCoreAsync(cancellationToken);

    private static DeviceEnrollmentStateSnapshot CreateSnapshot(
        VerifiedDeviceEnrollmentCredential verified)
    {
        var credential = verified.Credential;
        return new DeviceEnrollmentStateSnapshot(
            credential.CredentialSequence,
            verified.CredentialSha256,
            credential.EnrollmentId,
            credential.DeviceId,
            credential.PublicKeySha256,
            credential.RolloutRing.Value,
            credential.Status,
            credential.RevocationGeneration,
            credential.ExpiresUtc,
            credential.ManagementOrigin.AbsoluteUri);
    }

    private static void ValidateTransition(
        DeviceEnrollmentStateSnapshot current,
        DeviceEnrollmentStateSnapshot next)
    {
        if (!string.Equals(current.EnrollmentId, next.EnrollmentId, StringComparison.Ordinal) ||
            !string.Equals(current.DeviceId, next.DeviceId, StringComparison.Ordinal) ||
            !string.Equals(current.PublicKeySha256, next.PublicKeySha256, StringComparison.Ordinal) ||
            !string.Equals(current.ManagementOrigin, next.ManagementOrigin, StringComparison.Ordinal))
        {
            throw new DeviceManagementException(
                "The enrollment identity cannot change without an explicit reset.");
        }

        if (next.CredentialSequence < current.CredentialSequence)
        {
            throw new DeviceManagementException(
                "The enrollment credential sequence is lower than the anti-rollback floor.");
        }

        if (next.RevocationGeneration < current.RevocationGeneration)
        {
            throw new DeviceManagementException(
                "The enrollment revocation generation is lower than the anti-rollback floor.");
        }

        if (next.CredentialSequence == current.CredentialSequence &&
            !string.Equals(
                next.CredentialSha256,
                current.CredentialSha256,
                StringComparison.Ordinal))
        {
            throw new DeviceManagementException(
                "The enrollment credential changed without increasing its sequence.");
        }

        if (current.Status == DeviceEnrollmentStatus.Revoked &&
            next.Status != DeviceEnrollmentStatus.Revoked)
        {
            throw new DeviceManagementException(
                "A revoked enrollment cannot be reactivated without an explicit reset.");
        }
    }

    private async ValueTask<DeviceEnrollmentStateSnapshot?> LoadCoreAsync(
        CancellationToken cancellationToken)
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
            throw new DeviceManagementException("The enrollment state file is unsafe.");
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(statePath, cancellationToken).ConfigureAwait(false);
            if (bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble))
            {
                throw new DeviceManagementException(
                    "The enrollment state must be UTF-8 without a byte-order mark.");
            }

            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            EnsureUniqueProperties(document.RootElement);
            var state = document.RootElement.Deserialize<StateDocument>(SerializerOptions) ??
                throw new DeviceManagementException("The enrollment state is empty.");
            if (state.SchemaVersion != 1 ||
                state.CredentialSequence is null ||
                state.RevocationGeneration is null ||
                state.ExpiresUtc is null ||
                !Enum.TryParse<DeviceEnrollmentStatus>(state.Status, false, out var status) ||
                !Enum.IsDefined(status))
            {
                throw new DeviceManagementException(
                    "The enrollment state schema or a required property is invalid.");
            }

            return ValidateSnapshot(new DeviceEnrollmentStateSnapshot(
                state.CredentialSequence.Value,
                state.CredentialSha256!,
                state.EnrollmentId!,
                state.DeviceId!,
                state.PublicKeySha256!,
                state.RolloutRing!,
                status,
                state.RevocationGeneration.Value,
                state.ExpiresUtc.Value.ToUniversalTime(),
                state.ManagementOrigin!));
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or
                ArgumentException or NotSupportedException)
        {
            throw new DeviceManagementException("The enrollment state could not be read.", exception);
        }
    }

    private static DeviceEnrollmentStateSnapshot ValidateSnapshot(
        DeviceEnrollmentStateSnapshot state)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(state.CredentialSequence);
        ArgumentOutOfRangeException.ThrowIfNegative(state.RevocationGeneration);
        ValidateHex(state.CredentialSha256, 64);
        ValidateIdentifier(state.EnrollmentId, 128);
        ValidateHex(state.DeviceId, 32);
        ValidateHex(state.PublicKeySha256, 64);
        _ = new RolloutRing(state.RolloutRing);
        _ = DeviceEnrollmentCredential.NormalizeManagementOrigin(
            new Uri(state.ManagementOrigin, UriKind.Absolute));
        return state;
    }

    private static void ValidateHex(string? value, int length)
    {
        if (string.IsNullOrEmpty(value) || value.Length != length || value.Any(character =>
                !char.IsAsciiDigit(character) &&
                character is not (>= 'a' and <= 'f')))
        {
            throw new DeviceManagementException("The enrollment state contains invalid hexadecimal data.");
        }
    }

    private static void ValidateIdentifier(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximumLength ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            !char.IsAsciiLetterOrDigit(value[^1]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_' and not ':'))
        {
            throw new DeviceManagementException("The enrollment state contains an invalid identifier.");
        }
    }

    private async ValueTask WriteAsync(
        DeviceEnrollmentStateSnapshot state,
        CancellationToken cancellationToken)
    {
        var document = new StateDocument(
            1,
            state.CredentialSequence,
            state.CredentialSha256,
            state.EnrollmentId,
            state.DeviceId,
            state.PublicKeySha256,
            state.RolloutRing,
            state.Status.ToString(),
            state.RevocationGeneration,
            state.ExpiresUtc,
            state.ManagementOrigin);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document, SerializerOptions);
        var temporaryPath = statePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllBytesAsync(temporaryPath, bytes, cancellationToken).ConfigureAwait(false);
            File.Move(temporaryPath, statePath, overwrite: true);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException(
                "The enrollment state could not be committed.",
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
            throw new DeviceManagementException("The enrollment state must be a JSON object.");
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
        long? CredentialSequence,
        string? CredentialSha256,
        string? EnrollmentId,
        string? DeviceId,
        string? PublicKeySha256,
        string? RolloutRing,
        string? Status,
        long? RevocationGeneration,
        DateTimeOffset? ExpiresUtc,
        string? ManagementOrigin);
}
