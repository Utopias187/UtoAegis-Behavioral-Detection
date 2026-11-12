using UtoAegis.Core.Response;
using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Guard.Tests;

[TestClass]
public sealed class RuntimeIntegrityGuardEngineTests
{
    [TestMethod]
    public async Task RunAsync_Healthy_DoesNotReserveRecovery()
    {
        var platform = new StubPlatform([], []);
        var limiter = new StubLimiter(true);
        var engine = new RuntimeIntegrityGuardEngine(platform, limiter);

        var result = await engine.RunAsync(CreatePolicy(), recover: true);

        Assert.IsTrue(result.IsHealthy);
        Assert.IsFalse(result.RecoveryAttempted);
        Assert.AreEqual(0, limiter.CallCount);
    }

    [TestMethod]
    public async Task RunAsync_AuditOnly_ReportsDriftWithoutRecovery()
    {
        var finding = RecoverableFinding();
        var platform = new StubPlatform([finding], []);
        var limiter = new StubLimiter(true);
        var engine = new RuntimeIntegrityGuardEngine(platform, limiter);

        var result = await engine.RunAsync(CreatePolicy(), recover: false);

        Assert.IsFalse(result.IsHealthy);
        Assert.IsFalse(result.RecoveryAttempted);
        Assert.AreEqual(0, platform.RecoveryCount);
        Assert.AreEqual(0, limiter.CallCount);
    }

    [TestMethod]
    public async Task RunAsync_AuthorizedRecovery_ReauditsHealthyState()
    {
        var finding = RecoverableFinding();
        var platform = new StubPlatform([finding], []);
        var limiter = new StubLimiter(true);
        var engine = new RuntimeIntegrityGuardEngine(platform, limiter);

        var result = await engine.RunAsync(CreatePolicy(), recover: true);

        Assert.IsTrue(result.IsHealthy);
        Assert.IsTrue(result.RecoveryAttempted);
        Assert.AreEqual(1, platform.RecoveryCount);
        Assert.AreEqual(2, platform.AuditCount);
    }

    [TestMethod]
    public async Task RunAsync_MultipleServiceDrifts_RepairsServiceOnce()
    {
        var findings = new[]
        {
            RecoverableFinding(),
            new RuntimeIntegrityFinding(
                RuntimeIntegrityFindingKind.ServiceBinaryPathMismatch,
                "UtoAegis",
                "expected.exe",
                "changed.exe",
                true,
                "changed")
        };
        var platform = new StubPlatform(findings, []);
        var engine = new RuntimeIntegrityGuardEngine(platform, new StubLimiter(true));

        var result = await engine.RunAsync(CreatePolicy(), recover: true);

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(1, platform.RecoveryCount);
    }

    [TestMethod]
    public async Task RunAsync_RecoveryRateLimited_PreservesFinding()
    {
        var finding = RecoverableFinding();
        var platform = new StubPlatform([finding], []);
        var engine = new RuntimeIntegrityGuardEngine(platform, new StubLimiter(false));

        var result = await engine.RunAsync(CreatePolicy(), recover: true);

        Assert.IsFalse(result.IsHealthy);
        Assert.IsTrue(result.RecoveryRateLimited);
        Assert.IsFalse(result.RecoveryAttempted);
        Assert.AreEqual(0, platform.RecoveryCount);
    }

    [TestMethod]
    public async Task RunAsync_NonrecoverableFinding_DoesNotConsumeRecovery()
    {
        var finding = new RuntimeIntegrityFinding(
            RuntimeIntegrityFindingKind.ExecutableHashMismatch,
            "service.exe",
            new string('a', 64),
            new string('b', 64),
            false,
            "changed");
        var platform = new StubPlatform([finding], []);
        var limiter = new StubLimiter(true);
        var engine = new RuntimeIntegrityGuardEngine(platform, limiter);

        var result = await engine.RunAsync(CreatePolicy(), recover: true);

        Assert.IsFalse(result.IsHealthy);
        Assert.AreEqual(0, limiter.CallCount);
        Assert.AreEqual(0, platform.RecoveryCount);
    }

    [TestMethod]
    public async Task RunAsync_RecoveryFailure_RemainsVisible()
    {
        var finding = RecoverableFinding();
        var platform = new StubPlatform([finding], [finding], failRecovery: true);
        var engine = new RuntimeIntegrityGuardEngine(platform, new StubLimiter(true));

        var result = await engine.RunAsync(CreatePolicy(), recover: true);

        Assert.IsFalse(result.IsHealthy);
        Assert.IsTrue(result.RecoveryAttempted);
        Assert.IsTrue(result.RemainingFindings.Any(candidate =>
            candidate.Kind == RuntimeIntegrityFindingKind.RecoveryFailed));
    }

    private static RuntimePolicyManifest CreatePolicy() =>
        new(
            7,
            "endpoint-policy",
            "policy-key-1",
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            new ResponsePolicy(),
            [new RuntimeServicePolicy(
                "UtoAegis",
                Path.GetFullPath("utoaegis-service.exe"),
                new string('a', 64),
                @"NT SERVICE\UtoAegis",
                RuntimeServiceStartMode.DelayedAutomatic,
                true)],
            [],
            TimeSpan.FromMinutes(5),
            2,
            TimeSpan.FromHours(1));

    private static RuntimeIntegrityFinding RecoverableFinding() =>
        new(
            RuntimeIntegrityFindingKind.ServiceStartModeMismatch,
            "UtoAegis",
            "DelayedAutomatic",
            "Manual",
            true,
            "changed");

    private sealed class StubLimiter(bool allow) : IRuntimeRecoveryLimiter
    {
        public int CallCount { get; private set; }

        public ValueTask<bool> TryReserveAsync(
            RuntimePolicyManifest policy,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return ValueTask.FromResult(allow);
        }
    }

    private sealed class StubPlatform(
        IReadOnlyList<RuntimeIntegrityFinding> initial,
        IReadOnlyList<RuntimeIntegrityFinding> afterRecovery,
        bool failRecovery = false) : IRuntimeIntegrityPlatform
    {
        public int AuditCount { get; private set; }

        public int RecoveryCount { get; private set; }

        public ValueTask<IReadOnlyList<RuntimeIntegrityFinding>> AuditAsync(
            RuntimePolicyManifest policy,
            CancellationToken cancellationToken)
        {
            var result = AuditCount++ == 0 ? initial : afterRecovery;
            return ValueTask.FromResult(result);
        }

        public ValueTask RecoverAsync(
            RuntimeIntegrityFinding finding,
            RuntimePolicyManifest policy,
            CancellationToken cancellationToken)
        {
            RecoveryCount++;
            return failRecovery
                ? ValueTask.FromException(new InvalidOperationException("repair failed"))
                : ValueTask.CompletedTask;
        }
    }
}
