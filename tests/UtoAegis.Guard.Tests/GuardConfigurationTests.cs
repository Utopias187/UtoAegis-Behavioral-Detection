using System.Text.Json;

namespace UtoAegis.Guard.Tests;

[TestClass]
public sealed class GuardConfigurationTests
{
    private string testDirectory = null!;
    private string externalRoot = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Guard.Configuration.Tests",
            Guid.NewGuid().ToString("N"));
        externalRoot = testDirectory + "-external";
        Directory.CreateDirectory(testDirectory);
        Directory.CreateDirectory(externalRoot);
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }

        if (Directory.Exists(externalRoot))
        {
            Directory.Delete(externalRoot, recursive: true);
        }
    }

    [TestMethod]
    public void Load_IsolatedConfiguration_ResolvesAllPaths()
    {
        var path = WriteConfiguration();

        var result = GuardConfiguration.Load(path, testDirectory);

        Assert.AreEqual(Path.Combine(externalRoot, "policy"), result.PolicyBundlePath);
        Assert.AreEqual("endpoint-001", result.DeploymentId);
        Assert.AreEqual(512, result.TelemetryMaximumRecords);
        Assert.AreEqual(
            Path.Combine(externalRoot, "policy-key.pem"),
            result.TrustedSigningKeyPaths["policy-key-1"]);
    }

    [TestMethod]
    public void Load_KeyInsideWritableState_RejectsConfiguration()
    {
        var stateDirectory = Path.Combine(externalRoot, "state");
        Directory.CreateDirectory(stateDirectory);
        var unsafeKey = Path.Combine(stateDirectory, "policy-key.pem");
        File.WriteAllText(unsafeKey, "public key");
        var path = WriteConfiguration(unsafeKey);

        var exception = Assert.ThrowsExactly<GuardConfigurationException>(() =>
            GuardConfiguration.Load(path, testDirectory));

        StringAssert.Contains(exception.Message, "outside writable guard state");
    }

    private string WriteConfiguration(string? keyPath = null)
    {
        var policy = Path.Combine(externalRoot, "policy");
        Directory.CreateDirectory(policy);
        keyPath ??= Path.Combine(externalRoot, "policy-key.pem");
        if (!File.Exists(keyPath))
        {
            File.WriteAllText(keyPath, "public key");
        }

        var document = new
        {
            UtoAegisGuard = new
            {
                PolicyBundlePath = policy,
                PolicyStatePath = Path.Combine(externalRoot, "state", "policy-state.json"),
                TrustedSigningKeys = new[]
                {
                    new { KeyId = "policy-key-1", PublicKeyPath = keyPath }
                },
                RecoveryStatePath = Path.Combine(externalRoot, "state", "recovery-state.json"),
                SecurityTelemetrySpoolPath = Path.Combine(externalRoot, "telemetry"),
                DeploymentId = "endpoint-001",
                TelemetryMaximumRecords = 512
            }
        };
        var configurationPath = Path.Combine(testDirectory, "appsettings.json");
        File.WriteAllBytes(configurationPath, JsonSerializer.SerializeToUtf8Bytes(document));
        return configurationPath;
    }
}
