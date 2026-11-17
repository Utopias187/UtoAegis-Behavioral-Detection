using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

internal static class EnrollmentCredentialReader
{
    public const int MaximumCredentialLength = 16 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 4,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static DeviceEnrollmentCredential Read(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty || bytes.Length > MaximumCredentialLength ||
            bytes.StartsWith(Encoding.UTF8.Preamble))
        {
            throw new DeviceManagementException(
                "The enrollment credential is empty, oversized, or contains a byte-order mark.");
        }

        try
        {
            var text = new UTF8Encoding(false, true).GetString(bytes);
            using var document = JsonDocument.Parse(text, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            EnsureUniqueProperties(document.RootElement);
            var credential = document.RootElement.Deserialize<CredentialDocument>(SerializerOptions) ??
                throw new DeviceManagementException("The enrollment credential must be a JSON object.");
            if (credential.SchemaVersion != DeviceEnrollmentCredential.CurrentSchemaVersion ||
                !string.Equals(
                    credential.Algorithm,
                    DeviceEnrollmentCredential.SignatureAlgorithm,
                    StringComparison.Ordinal) ||
                credential.CredentialSequence is null ||
                credential.RevocationGeneration is null ||
                credential.IssuedUtc is null ||
                credential.ExpiresUtc is null ||
                !Enum.TryParse<DeviceEnrollmentStatus>(credential.Status, false, out var status) ||
                !Enum.IsDefined(status) ||
                !Uri.TryCreate(credential.ManagementOrigin, UriKind.Absolute, out var origin))
            {
                throw new DeviceManagementException(
                    "The enrollment credential schema or a required property is invalid.");
            }

            return new DeviceEnrollmentCredential(
                credential.CredentialSequence.Value,
                credential.EnrollmentId!,
                credential.DeviceId!,
                credential.PublicKeySha256!,
                new RolloutRing(credential.RolloutRing!),
                status,
                credential.RevocationGeneration.Value,
                credential.IssuedUtc.Value,
                credential.ExpiresUtc.Value,
                origin,
                credential.KeyId!);
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException or DecoderFallbackException or ArgumentException or
                NotSupportedException or OverflowException)
        {
            throw new DeviceManagementException("The enrollment credential is not valid.", exception);
        }
    }

    private static void EnsureUniqueProperties(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new DeviceManagementException(
                "The enrollment credential must contain a JSON object.");
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

    private sealed record CredentialDocument(
        int? SchemaVersion,
        string? Algorithm,
        long? CredentialSequence,
        string? EnrollmentId,
        string? DeviceId,
        string? PublicKeySha256,
        string? RolloutRing,
        string? Status,
        long? RevocationGeneration,
        DateTimeOffset? IssuedUtc,
        DateTimeOffset? ExpiresUtc,
        string? ManagementOrigin,
        string? KeyId);
}
