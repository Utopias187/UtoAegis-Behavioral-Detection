using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UtoAegis.Core.Management;
using UtoAegis.Core.RuntimeIntegrity;
using UtoAegis.Infrastructure.Management;
using UtoAegis.Infrastructure.RuntimeIntegrity;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SignedPolicyDistributionVerifierTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 17, 18, 0, 0, TimeSpan.Zero);

    private string testDirectory = null!;
    private ECDsa signingKey = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.PolicyDistribution.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDirectory);
        signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    [TestCleanup]
    public void Cleanup()
    {
        signingKey.Dispose();
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task VerifyAsync_AuthorizedRing_ReturnsExactPolicy()
    {
        var package = await CreatePackageAsync();

        var result = await CreateVerifier().VerifyAsync(package, CreateEnrollment());

        Assert.AreEqual("endpoint-policy", result.Authorization.PolicyId);
        Assert.AreEqual(17L, result.RuntimePolicy.Manifest.Sequence);
        Assert.AreEqual("canary", result.Authorization.AllowedRolloutRings[0].Value);
        Assert.AreEqual(64, result.AuthorizationSha256.Length);
    }

    [TestMethod]
    public async Task VerifyAsync_UnauthorizedRing_RejectsPackage()
    {
        var package = await CreatePackageAsync(allowedRings: ["pilot", "stable"]);

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(package, CreateEnrollment()));

        StringAssert.Contains(exception.Message, "Rollout ring");
    }

    [TestMethod]
    public async Task VerifyAsync_TamperedAuthorization_RejectsSignature()
    {
        var package = await CreatePackageAsync();
        var path = Path.Combine(
            package,
            SignedPolicyDistributionVerifier.AuthorizationFileName);
        var json = await File.ReadAllTextAsync(path);
        await File.WriteAllTextAsync(path, json.Replace("canary", "stable"));

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(package, CreateEnrollment()));

        StringAssert.Contains(exception.Message, "signature");
    }

    [TestMethod]
    public async Task VerifyAsync_MismatchedManifestHash_RejectsPackage()
    {
        var package = await CreatePackageAsync(manifestSha256: new string('0', 64));

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(package, CreateEnrollment()));

        StringAssert.Contains(exception.Message, "does not match");
    }

    [TestMethod]
    public async Task VerifyAsync_MismatchedPolicyIdentity_RejectsPackage()
    {
        var package = await CreatePackageAsync(
            authorizationPolicyId: "different-policy",
            authorizationPolicySequence: 18);

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(package, CreateEnrollment()));

        StringAssert.Contains(exception.Message, "does not match");
    }

    [TestMethod]
    public async Task VerifyAsync_ExpiredAuthorization_RejectsPackage()
    {
        var package = await CreatePackageAsync(
            authorizationIssuedUtc: Now.AddDays(-2),
            authorizationExpiresUtc: Now.AddHours(-1));

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(package, CreateEnrollment()));

        StringAssert.Contains(exception.Message, "authorization has expired");
    }

    [TestMethod]
    [DataRow(DeviceEnrollmentStatus.Suspended)]
    [DataRow(DeviceEnrollmentStatus.Revoked)]
    public async Task VerifyAsync_InactiveEnrollment_RejectsPackage(DeviceEnrollmentStatus status)
    {
        var package = await CreatePackageAsync();

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(
                package,
                CreateEnrollment(status: status)));

        StringAssert.Contains(exception.Message, "active device enrollment");
    }

    [TestMethod]
    public async Task VerifyAsync_ExpiredEnrollment_RejectsPackage()
    {
        var package = await CreatePackageAsync();

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(
                package,
                CreateEnrollment(
                    issuedUtc: Now.AddDays(-30),
                    expiresUtc: Now.AddHours(-1))));

        StringAssert.Contains(exception.Message, "enrollment is outside");
    }

    [TestMethod]
    public async Task VerifyAsync_DuplicateAuthorizationProperty_RejectsPackage()
    {
        var package = await CreatePackageAsync();
        var path = Path.Combine(
            package,
            SignedPolicyDistributionVerifier.AuthorizationFileName);
        var bytes = await File.ReadAllBytesAsync(path);
        var json = Encoding.UTF8.GetString(bytes).Replace(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1");
        bytes = Encoding.UTF8.GetBytes(json);
        await File.WriteAllBytesAsync(path, bytes);
        await WriteSignatureAsync(
            Path.Combine(package, SignedPolicyDistributionVerifier.AuthorizationSignatureFileName),
            bytes);

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(package, CreateEnrollment()));

        StringAssert.Contains(exception.Message, "Duplicate JSON property");
    }

    [TestMethod]
    public async Task VerifyAsync_UnexpectedPackageEntry_RejectsPackage()
    {
        var package = await CreatePackageAsync();
        await File.WriteAllTextAsync(Path.Combine(package, "notes.txt"), "unexpected");

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(package, CreateEnrollment()));

        StringAssert.Contains(exception.Message, "must contain only");
    }

    private SignedPolicyDistributionVerifier CreateVerifier()
    {
        var trustedKey = new TrustedThreatSigningKey(
            "policy-key-1",
            signingKey.ExportSubjectPublicKeyInfoPem());
        return new SignedPolicyDistributionVerifier(
            new ThreatTrustStore([trustedKey]),
            new FixedTimeProvider(Now));
    }

    private static VerifiedDeviceEnrollmentCredential CreateEnrollment(
        string ring = "canary",
        DeviceEnrollmentStatus status = DeviceEnrollmentStatus.Active,
        DateTimeOffset? issuedUtc = null,
        DateTimeOffset? expiresUtc = null)
    {
        var credential = new DeviceEnrollmentCredential(
            3,
            "enrollment-1",
            new string('a', 32),
            new string('b', 64),
            new RolloutRing(ring),
            status,
            status == DeviceEnrollmentStatus.Revoked ? 1 : 0,
            issuedUtc ?? Now.AddDays(-1),
            expiresUtc ?? Now.AddDays(30),
            new Uri("https://management.example/"),
            "enrollment-key-1");
        return new VerifiedDeviceEnrollmentCredential(credential, new string('c', 64));
    }

    private async Task<string> CreatePackageAsync(
        IReadOnlyList<string>? allowedRings = null,
        string? manifestSha256 = null,
        string authorizationPolicyId = "endpoint-policy",
        long authorizationPolicySequence = 17,
        DateTimeOffset? authorizationIssuedUtc = null,
        DateTimeOffset? authorizationExpiresUtc = null)
    {
        var package = Path.Combine(testDirectory, "package-" + Guid.NewGuid().ToString("N"));
        var policyDirectory = Path.Combine(
            package,
            SignedPolicyDistributionVerifier.PolicyDirectoryName);
        Directory.CreateDirectory(policyDirectory);
        var manifestBytes = await WriteRuntimePolicyAsync(policyDirectory);
        var authorization = new
        {
            schemaVersion = PolicyDistributionAuthorization.CurrentSchemaVersion,
            algorithm = PolicyDistributionAuthorization.SignatureAlgorithm,
            authorizationSequence = 4,
            policyId = authorizationPolicyId,
            policySequence = authorizationPolicySequence,
            manifestSha256 = manifestSha256 ?? Convert.ToHexString(
                SHA256.HashData(manifestBytes)).ToLowerInvariant(),
            allowedRolloutRings = allowedRings ?? ["canary"],
            issuedUtc = authorizationIssuedUtc ?? Now.AddHours(-1),
            expiresUtc = authorizationExpiresUtc ?? Now.AddDays(7),
            keyId = "policy-key-1"
        };
        var authorizationBytes = JsonSerializer.SerializeToUtf8Bytes(authorization);
        await File.WriteAllBytesAsync(
            Path.Combine(package, SignedPolicyDistributionVerifier.AuthorizationFileName),
            authorizationBytes);
        await WriteSignatureAsync(
            Path.Combine(package, SignedPolicyDistributionVerifier.AuthorizationSignatureFileName),
            authorizationBytes);
        return package;
    }

    private async Task<byte[]> WriteRuntimePolicyAsync(string policyDirectory)
    {
        var document = new
        {
            schemaVersion = RuntimePolicyManifest.CurrentSchemaVersion,
            algorithm = RuntimePolicyManifest.SignatureAlgorithm,
            sequence = 17,
            policyId = "endpoint-policy",
            keyId = "policy-key-1",
            issuedUtc = Now.AddHours(-1),
            expiresUtc = Now.AddDays(30),
            response = new
            {
                mode = "ObserveOnly",
                allowlistedPathPrefixes = Array.Empty<string>(),
                allowlistedSha256 = Array.Empty<string>(),
                maxActionsPerWindow = 3,
                rateLimitWindowSeconds = 300
            },
            integrity = new
            {
                auditIntervalSeconds = 300,
                maximumRecoveriesPerWindow = 2,
                recoveryWindowSeconds = 3600,
                services = new[]
                {
                    new
                    {
                        name = "UtoAegis",
                        executablePath = Path.Combine(testDirectory, "utoaegis-service.exe"),
                        executableSha256 = new string('d', 64),
                        account = @"NT SERVICE\UtoAegis",
                        startMode = "DelayedAutomatic",
                        recover = true
                    }
                },
                paths = Array.Empty<object>()
            }
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document);
        await File.WriteAllBytesAsync(
            Path.Combine(policyDirectory, SignedRuntimePolicyVerifier.ManifestFileName),
            bytes);
        await WriteSignatureAsync(
            Path.Combine(policyDirectory, SignedRuntimePolicyVerifier.SignatureFileName),
            bytes);
        return bytes;
    }

    private async Task WriteSignatureAsync(string path, byte[] bytes)
    {
        var signature = signingKey.SignData(
            bytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        await File.WriteAllTextAsync(path, Convert.ToBase64String(signature));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
