using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.RuntimeIntegrity;

namespace UtoAegis.Infrastructure.Management;

public sealed record VerifiedPolicyDistribution(
    PolicyDistributionAuthorization Authorization,
    string AuthorizationSha256,
    VerifiedRuntimePolicy RuntimePolicy,
    string PackagePath);
