using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UtoAegis.Core.RuntimeIntegrity;
using UtoAegis.Infrastructure.RuntimeIntegrity;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SignedRuntimePolicyVerifierTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 12, 18, 0, 0, TimeSpan.Zero);

    private string testDirectory = null!;
    private ECDsa signingKey = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.RuntimePolicy.Tests",
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
    public async Task VerifyAsync_ValidPolicy_ReturnsAuthenticatedPolicy()
    {
        var bundle = await CreateBundleAsync();

        var result = await CreateVerifier().VerifyAsync(bundle);

        Assert.AreEqual(17L, result.Manifest.Sequence);
        Assert.AreEqual("endpoint-policy", result.Manifest.PolicyId);
        Assert.AreEqual(RuntimeServiceStartMode.DelayedAutomatic, result.Manifest.Services[0].StartMode);
        Assert.AreEqual(1, result.Manifest.Paths.Count);
        Assert.AreEqual(64, result.ManifestSha256.Length);
    }

    [TestMethod]
    public async Task VerifyAsync_TamperedPolicy_RejectsSignature()
    {
        var bundle = await CreateBundleAsync();
        var path = Path.Combine(bundle, SignedRuntimePolicyVerifier.ManifestFileName);
        var content = await File.ReadAllTextAsync(path);
        await File.WriteAllTextAsync(path, content.Replace("ObserveOnly", "DryRunQuarantine"));

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(bundle));

        StringAssert.Contains(exception.Message, "signature");
    }

    [TestMethod]
    public async Task VerifyAsync_ExpiredPolicy_RejectsPolicy()
    {
        var bundle = await CreateBundleAsync(expiresUtc: Now.AddMinutes(-10));

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(bundle));

        StringAssert.Contains(exception.Message, "expired");
    }

    [TestMethod]
    public async Task VerifyAsync_UnexpectedFile_RejectsBundle()
    {
        var bundle = await CreateBundleAsync();
        await File.WriteAllTextAsync(Path.Combine(bundle, "notes.txt"), "unexpected");

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(bundle));

        StringAssert.Contains(exception.Message, "only policy.json and policy.sig");
    }

    [TestMethod]
    public async Task VerifyAsync_DuplicateProperty_RejectsPolicy()
    {
        var bundle = await CreateBundleAsync();
        var path = Path.Combine(bundle, SignedRuntimePolicyVerifier.ManifestFileName);
        var bytes = await File.ReadAllBytesAsync(path);
        var json = Encoding.UTF8.GetString(bytes);
        json = json.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1");
        bytes = Encoding.UTF8.GetBytes(json);
        await File.WriteAllBytesAsync(path, bytes);
        await WriteSignatureAsync(bundle, bytes);

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await CreateVerifier().VerifyAsync(bundle));

        StringAssert.Contains(exception.Message, "Duplicate JSON property");
    }

    [TestMethod]
    public async Task AcceptAsync_LowerSequence_RejectsRollback()
    {
        var first = await CreateAndVerifyAsync(sequence: 18);
        var state = new RuntimePolicyStateStore(Path.Combine(testDirectory, "state", "policy-state.json"));
        await state.AcceptAsync(first);
        var older = await CreateAndVerifyAsync(sequence: 17);

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await state.AcceptAsync(older));

        StringAssert.Contains(exception.Message, "anti-rollback floor");
    }

    [TestMethod]
    public async Task AcceptAsync_SameSequenceAndHash_AllowsRestart()
    {
        var policy = await CreateAndVerifyAsync();
        var state = new RuntimePolicyStateStore(Path.Combine(testDirectory, "state", "policy-state.json"));

        await state.AcceptAsync(policy);
        await state.AcceptAsync(policy);
    }

    [TestMethod]
    public async Task AcceptAsync_SameSequenceChangedPolicy_RejectsEquivocation()
    {
        var state = new RuntimePolicyStateStore(Path.Combine(testDirectory, "state", "policy-state.json"));
        await state.AcceptAsync(await CreateAndVerifyAsync(policyId: "endpoint-policy-a"));
        var changed = await CreateAndVerifyAsync(policyId: "endpoint-policy-b");

        var exception = await Assert.ThrowsExactlyAsync<RuntimePolicyException>(
            async () => await state.AcceptAsync(changed));

        StringAssert.Contains(exception.Message, "without increasing its sequence");
    }

    private SignedRuntimePolicyVerifier CreateVerifier()
    {
        var trustedKey = new TrustedThreatSigningKey(
            "policy-key-1",
            signingKey.ExportSubjectPublicKeyInfoPem());
        return new SignedRuntimePolicyVerifier(
            new ThreatTrustStore([trustedKey]),
            new FixedTimeProvider(Now));
    }

    private async Task<VerifiedRuntimePolicy> CreateAndVerifyAsync(
        long sequence = 17,
        string policyId = "endpoint-policy")
    {
        var bundle = await CreateBundleAsync(sequence, policyId);
        return await CreateVerifier().VerifyAsync(bundle);
    }

    private async Task<string> CreateBundleAsync(
        long sequence = 17,
        string policyId = "endpoint-policy",
        DateTimeOffset? expiresUtc = null)
    {
        var bundle = Path.Combine(testDirectory, "bundle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(bundle);
        var executablePath = Path.Combine(testDirectory, "utoaegis-service.exe");
        var protectedPath = Path.Combine(testDirectory, "protected");
        var document = new
        {
            schemaVersion = RuntimePolicyManifest.CurrentSchemaVersion,
            algorithm = RuntimePolicyManifest.SignatureAlgorithm,
            sequence,
            policyId,
            keyId = "policy-key-1",
            issuedUtc = Now.AddHours(-1),
            expiresUtc = expiresUtc ?? Now.AddDays(30),
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
                        executablePath,
                        executableSha256 = new string('a', 64),
                        account = @"NT SERVICE\UtoAegis",
                        startMode = "DelayedAutomatic",
                        recover = true
                    }
                },
                paths = new[]
                {
                    new
                    {
                        path = protectedPath,
                        expectedSddl = "O:BAG:SYD:(A;;FA;;;SY)",
                        recover = true
                    }
                }
            }
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document);
        await File.WriteAllBytesAsync(
            Path.Combine(bundle, SignedRuntimePolicyVerifier.ManifestFileName),
            bytes);
        await WriteSignatureAsync(bundle, bytes);
        return bundle;
    }

    private async Task WriteSignatureAsync(string bundle, byte[] bytes)
    {
        var signature = signingKey.SignData(
            bytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        await File.WriteAllTextAsync(
            Path.Combine(bundle, SignedRuntimePolicyVerifier.SignatureFileName),
            Convert.ToBase64String(signature));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
