using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.RuntimeIntegrity;

namespace UtoAegis.Infrastructure.Management;

public sealed class PolicyAcknowledgementStore
{
    private const int MaximumStateLength = 8 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 4,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly string statePath;

    public PolicyAcknowledgementStore(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        this.statePath = Path.GetFullPath(statePath);
        var parent = Path.GetDirectoryName(this.statePath)!;
        if (Path.GetFullPath(parent) == Path.GetPathRoot(parent))
        {
            throw new ArgumentException(
                "The policy acknowledgement must not be stored at a filesystem root.",
                nameof(statePath));
        }
    }

    public async ValueTask<PolicyAcknowledgementState> RecordPendingAsync(
        VerifiedRuntimePolicy policy,
        DeviceEnrollmentStateSnapshot enrollment,
        DateTimeOffset appliedUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(enrollment);
        if (enrollment.Status != DeviceEnrollmentStatus.Active)
        {
            throw new DeviceManagementException(
                "Policy acknowledgement requires an active enrollment.");
        }

        var parent = Path.GetDirectoryName(statePath)!;
        Directory.CreateDirectory(parent);
        RejectReparsePoint(parent);
        await using var operationLock = await AcquireLockAsync(
            statePath + ".lock",
            cancellationToken).ConfigureAwait(false);
        var current = await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
        if (current is not null)
        {
            if (!string.Equals(
                    current.Acknowledgement.DeviceId,
                    enrollment.DeviceId,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    current.Acknowledgement.EnrollmentId,
                    enrollment.EnrollmentId,
                    StringComparison.Ordinal))
            {
                throw new DeviceManagementException(
                    "The policy acknowledgement enrollment cannot change without an explicit reset.");
            }

            ValidatePolicyTransition(current, policy);
            if (current.Acknowledgement.PolicySequence == policy.Manifest.Sequence)
            {
                return current;
            }

            if (current.IsPending)
            {
                throw new DeviceManagementException(
                    "The pending policy acknowledgement must be delivered before it can be replaced.");
            }
        }

        var acknowledgement = new PolicyAcknowledgement(
            Guid.NewGuid().ToString("N"),
            enrollment.DeviceId,
            enrollment.EnrollmentId,
            policy.Manifest.PolicyId,
            policy.Manifest.Sequence,
            policy.ManifestSha256,
            appliedUtc);
        var next = new PolicyAcknowledgementState(acknowledgement, null);
        await WriteAsync(next, cancellationToken).ConfigureAwait(false);
        return next;
    }

    public async ValueTask<PolicyAcknowledgementState> MarkDeliveredAsync(
        string acknowledgementId,
        DateTimeOffset confirmedUtc,
        CancellationToken cancellationToken = default)
    {
        var normalizedId = NormalizeHex(acknowledgementId, 32, nameof(acknowledgementId));
        ArgumentOutOfRangeException.ThrowIfEqual(confirmedUtc, default, nameof(confirmedUtc));
        var parent = Path.GetDirectoryName(statePath)!;
        Directory.CreateDirectory(parent);
        RejectReparsePoint(parent);
        await using var operationLock = await AcquireLockAsync(
            statePath + ".lock",
            cancellationToken).ConfigureAwait(false);
        var current = await LoadCoreAsync(cancellationToken).ConfigureAwait(false) ??
            throw new DeviceManagementException("No policy acknowledgement is available.");
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(normalizedId),
                Convert.FromHexString(current.Acknowledgement.AcknowledgementId)))
        {
            throw new DeviceManagementException(
                "The server confirmation does not match the pending policy acknowledgement.");
        }

        if (!current.IsPending)
        {
            return current;
        }

        var confirmed = confirmedUtc.ToUniversalTime();
        if (confirmed < current.Acknowledgement.AppliedUtc)
        {
            throw new DeviceManagementException(
                "Policy acknowledgement confirmation predates policy application.");
        }

        var delivered = current with { DeliveredUtc = confirmed };
        await WriteAsync(delivered, cancellationToken).ConfigureAwait(false);
        return delivered;
    }

    public ValueTask<PolicyAcknowledgementState?> LoadAsync(
        CancellationToken cancellationToken = default) =>
        LoadCoreAsync(cancellationToken);

    private static void ValidatePolicyTransition(
        PolicyAcknowledgementState current,
        VerifiedRuntimePolicy policy)
    {
        var acknowledgement = current.Acknowledgement;
        if (policy.Manifest.Sequence < acknowledgement.PolicySequence)
        {
            throw new DeviceManagementException(
                "The policy acknowledgement sequence is lower than the durable floor.");
        }

        if (policy.Manifest.Sequence == acknowledgement.PolicySequence &&
            (!string.Equals(
                policy.Manifest.PolicyId,
                acknowledgement.PolicyId,
                StringComparison.Ordinal) ||
             !CryptographicOperations.FixedTimeEquals(
                 Convert.FromHexString(policy.ManifestSha256),
                 Convert.FromHexString(acknowledgement.ManifestSha256))))
        {
            throw new DeviceManagementException(
                "The acknowledged policy changed without increasing its sequence.");
        }
    }

    private async ValueTask<PolicyAcknowledgementState?> LoadCoreAsync(
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
            throw new DeviceManagementException(
                "The policy acknowledgement state file is unsafe.");
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(statePath, cancellationToken)
                .ConfigureAwait(false);
            if (bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble))
            {
                throw new DeviceManagementException(
                    "The policy acknowledgement state must be UTF-8 without a byte-order mark.");
            }

            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            EnsureUniqueProperties(document.RootElement);
            var state = document.RootElement.Deserialize<StateDocument>(SerializerOptions) ??
                throw new DeviceManagementException(
                    "The policy acknowledgement state is empty.");
            if (state.SchemaVersion != PolicyAcknowledgement.CurrentSchemaVersion ||
                state.PolicySequence is null || state.AppliedUtc is null)
            {
                throw new DeviceManagementException(
                    "The policy acknowledgement state schema is invalid.");
            }

            var acknowledgement = new PolicyAcknowledgement(
                state.AcknowledgementId!,
                state.DeviceId!,
                state.EnrollmentId!,
                state.PolicyId!,
                state.PolicySequence.Value,
                state.ManifestSha256!,
                state.AppliedUtc.Value);
            var deliveredUtc = state.DeliveredUtc?.ToUniversalTime();
            if (deliveredUtc < acknowledgement.AppliedUtc)
            {
                throw new DeviceManagementException(
                    "The policy acknowledgement delivery timestamp is invalid.");
            }

            return new PolicyAcknowledgementState(acknowledgement, deliveredUtc);
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
                "The policy acknowledgement state could not be read.",
                exception);
        }
    }

    private async ValueTask WriteAsync(
        PolicyAcknowledgementState state,
        CancellationToken cancellationToken)
    {
        var acknowledgement = state.Acknowledgement;
        var document = new StateDocument(
            acknowledgement.SchemaVersion,
            acknowledgement.AcknowledgementId,
            acknowledgement.DeviceId,
            acknowledgement.EnrollmentId,
            acknowledgement.PolicyId,
            acknowledgement.PolicySequence,
            acknowledgement.ManifestSha256,
            acknowledgement.AppliedUtc,
            state.DeliveredUtc);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document, SerializerOptions);
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
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException(
                "The policy acknowledgement state could not be committed.",
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

    private static void RejectReparsePoint(string parent)
    {
        var directory = new DirectoryInfo(parent);
        directory.Refresh();
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new DeviceManagementException(
                "The policy acknowledgement state directory must not be a reparse point.");
        }
    }

    private static void EnsureUniqueProperties(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new DeviceManagementException(
                "The policy acknowledgement state must be a JSON object.");
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

    private static string NormalizeHex(string value, int length, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length != length || value.Any(character =>
                !char.IsAsciiDigit(character) &&
                character is not (>= 'a' and <= 'f') and not (>= 'A' and <= 'F')))
        {
            throw new ArgumentException(
                $"The value must contain exactly {length} hexadecimal characters.",
                parameterName);
        }

        return value.ToLowerInvariant();
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
        string? AcknowledgementId,
        string? DeviceId,
        string? EnrollmentId,
        string? PolicyId,
        long? PolicySequence,
        string? ManifestSha256,
        DateTimeOffset? AppliedUtc,
        DateTimeOffset? DeliveredUtc);
}
