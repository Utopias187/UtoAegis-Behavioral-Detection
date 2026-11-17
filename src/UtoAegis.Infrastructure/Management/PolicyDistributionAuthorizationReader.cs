using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.RuntimeIntegrity;

namespace UtoAegis.Infrastructure.Management;

internal static class PolicyDistributionAuthorizationReader
{
    public const int MaximumAuthorizationLength = 16 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 6,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 6
    };

    public static PolicyDistributionAuthorization Read(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty || bytes.Length > MaximumAuthorizationLength)
        {
            throw new RuntimePolicyException(
                $"The policy distribution authorization must contain 1 to {MaximumAuthorizationLength} bytes.");
        }

        if (bytes.StartsWith(Encoding.UTF8.Preamble))
        {
            throw new RuntimePolicyException(
                "The policy distribution authorization must be UTF-8 without a byte-order mark.");
        }

        try
        {
            var json = new UTF8Encoding(false, true).GetString(bytes);
            using var document = JsonDocument.Parse(json, DocumentOptions);
            EnsureUniqueProperties(document.RootElement);
            var authorization = document.RootElement.Deserialize<AuthorizationDocument>(SerializerOptions) ??
                throw new RuntimePolicyException(
                    "The policy distribution authorization must contain a JSON object.");
            if (authorization.SchemaVersion != PolicyDistributionAuthorization.CurrentSchemaVersion)
            {
                throw new RuntimePolicyException(
                    $"Unsupported policy distribution authorization schema version '{authorization.SchemaVersion}'.");
            }

            if (!string.Equals(
                    authorization.Algorithm,
                    PolicyDistributionAuthorization.SignatureAlgorithm,
                    StringComparison.Ordinal))
            {
                throw new RuntimePolicyException(
                    "The policy distribution authorization uses an unsupported signature algorithm.");
            }

            if (authorization.AuthorizationSequence is null ||
                authorization.PolicySequence is null ||
                authorization.AllowedRolloutRings is null ||
                authorization.IssuedUtc is null ||
                authorization.ExpiresUtc is null)
            {
                throw new RuntimePolicyException(
                    "The policy distribution authorization is missing a required property.");
            }

            return new PolicyDistributionAuthorization(
                authorization.AuthorizationSequence.Value,
                authorization.PolicyId!,
                authorization.PolicySequence.Value,
                authorization.ManifestSha256!,
                authorization.AllowedRolloutRings.Select(ring => new RolloutRing(ring)).ToArray(),
                authorization.IssuedUtc.Value,
                authorization.ExpiresUtc.Value,
                authorization.KeyId!);
        }
        catch (RuntimePolicyException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException or DecoderFallbackException or ArgumentException or
                NotSupportedException or OverflowException)
        {
            throw new RuntimePolicyException(
                "The policy distribution authorization is not valid.",
                exception);
        }
    }

    private static void EnsureUniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new RuntimePolicyException(
                        $"Duplicate JSON property '{property.Name}' is not allowed.");
                }

                EnsureUniqueProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                EnsureUniqueProperties(item);
            }
        }
    }

    private sealed record AuthorizationDocument(
        int? SchemaVersion,
        string? Algorithm,
        long? AuthorizationSequence,
        string? PolicyId,
        long? PolicySequence,
        string? ManifestSha256,
        IReadOnlyList<string>? AllowedRolloutRings,
        DateTimeOffset? IssuedUtc,
        DateTimeOffset? ExpiresUtc,
        string? KeyId);
}
