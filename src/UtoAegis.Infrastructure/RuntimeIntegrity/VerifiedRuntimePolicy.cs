using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Infrastructure.RuntimeIntegrity;

public sealed record VerifiedRuntimePolicy(
    RuntimePolicyManifest Manifest,
    string ManifestSha256,
    string BundlePath);
