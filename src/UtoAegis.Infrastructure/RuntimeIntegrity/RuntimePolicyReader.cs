using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UtoAegis.Core.Response;
using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Infrastructure.RuntimeIntegrity;

internal static class RuntimePolicyReader
{
    public const int MaximumManifestLength = 256 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 12,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 12
    };

    public static RuntimePolicyManifest Read(ReadOnlySpan<byte> manifestBytes)
    {
        if (manifestBytes.IsEmpty || manifestBytes.Length > MaximumManifestLength)
        {
            throw new RuntimePolicyException(
                $"The runtime policy must contain 1 to {MaximumManifestLength} bytes.");
        }

        if (manifestBytes.StartsWith(Encoding.UTF8.Preamble))
        {
            throw new RuntimePolicyException(
                "The runtime policy must be UTF-8 without a byte-order mark.");
        }

        try
        {
            var json = new UTF8Encoding(false, true).GetString(manifestBytes);
            using var document = JsonDocument.Parse(json, DocumentOptions);
            EnsureUniqueProperties(document.RootElement);
            var policy = document.RootElement.Deserialize<PolicyDocument>(SerializerOptions) ??
                throw new RuntimePolicyException("The runtime policy must contain a JSON object.");
            if (policy.SchemaVersion != RuntimePolicyManifest.CurrentSchemaVersion)
            {
                throw new RuntimePolicyException(
                    $"Unsupported runtime policy schema version '{policy.SchemaVersion}'.");
            }

            if (!string.Equals(
                    policy.Algorithm,
                    RuntimePolicyManifest.SignatureAlgorithm,
                    StringComparison.Ordinal))
            {
                throw new RuntimePolicyException(
                    "The runtime policy uses an unsupported signature algorithm.");
            }

            if (policy.Sequence is null || policy.IssuedUtc is null || policy.ExpiresUtc is null ||
                policy.Response is null || policy.Integrity is null ||
                policy.Integrity.AuditIntervalSeconds is null ||
                policy.Integrity.MaximumRecoveriesPerWindow is null ||
                policy.Integrity.RecoveryWindowSeconds is null ||
                policy.Integrity.Services is null || policy.Integrity.Paths is null)
            {
                throw new RuntimePolicyException("The runtime policy is missing a required property.");
            }

            if (!Enum.TryParse<ResponseMode>(policy.Response.Mode, true, out var responseMode) ||
                !Enum.IsDefined(responseMode))
            {
                throw new RuntimePolicyException("The runtime response mode is not valid.");
            }

            var responsePolicy = new ResponsePolicy(
                responseMode,
                policy.Response.AllowlistedPathPrefixes ?? [],
                policy.Response.AllowlistedSha256 ?? [],
                policy.Response.MaxActionsPerWindow ?? 3,
                TimeSpan.FromSeconds(policy.Response.RateLimitWindowSeconds ?? 300));
            var services = policy.Integrity.Services.Select(ParseService).ToArray();
            var paths = policy.Integrity.Paths.Select(ParsePath).ToArray();
            return new RuntimePolicyManifest(
                policy.Sequence.Value,
                policy.PolicyId!,
                policy.KeyId!,
                policy.IssuedUtc.Value,
                policy.ExpiresUtc.Value,
                responsePolicy,
                services,
                paths,
                TimeSpan.FromSeconds(policy.Integrity.AuditIntervalSeconds.Value),
                policy.Integrity.MaximumRecoveriesPerWindow.Value,
                TimeSpan.FromSeconds(policy.Integrity.RecoveryWindowSeconds.Value));
        }
        catch (RuntimePolicyException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException or DecoderFallbackException or ArgumentException or
                NotSupportedException or OverflowException)
        {
            throw new RuntimePolicyException("The runtime policy is not valid.", exception);
        }
    }

    private static RuntimeServicePolicy ParseService(ServiceDocument service)
    {
        if (!Enum.TryParse<RuntimeServiceStartMode>(service.StartMode, true, out var startMode) ||
            !Enum.IsDefined(startMode))
        {
            throw new RuntimePolicyException(
                $"Runtime service '{service.Name}' has an invalid start mode.");
        }

        return new RuntimeServicePolicy(
            service.Name!,
            service.ExecutablePath!,
            service.ExecutableSha256!,
            service.Account!,
            startMode,
            service.Recover ?? false);
    }

    private static RuntimePathPolicy ParsePath(PathDocument path) =>
        new(path.Path!, path.ExpectedSddl!, path.Recover ?? false);

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

    private sealed record PolicyDocument(
        int? SchemaVersion,
        string? Algorithm,
        long? Sequence,
        string? PolicyId,
        string? KeyId,
        DateTimeOffset? IssuedUtc,
        DateTimeOffset? ExpiresUtc,
        ResponseDocument? Response,
        IntegrityDocument? Integrity);

    private sealed record ResponseDocument(
        string? Mode,
        IReadOnlyList<string>? AllowlistedPathPrefixes,
        IReadOnlyList<string>? AllowlistedSha256,
        int? MaxActionsPerWindow,
        int? RateLimitWindowSeconds);

    private sealed record IntegrityDocument(
        int? AuditIntervalSeconds,
        int? MaximumRecoveriesPerWindow,
        int? RecoveryWindowSeconds,
        IReadOnlyList<ServiceDocument>? Services,
        IReadOnlyList<PathDocument>? Paths);

    private sealed record ServiceDocument(
        string? Name,
        string? ExecutablePath,
        string? ExecutableSha256,
        string? Account,
        string? StartMode,
        bool? Recover);

    private sealed record PathDocument(string? Path, string? ExpectedSddl, bool? Recover);
}
