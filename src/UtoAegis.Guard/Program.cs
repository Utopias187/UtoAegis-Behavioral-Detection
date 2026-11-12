using System.Text.Json;
using UtoAegis.Infrastructure.RuntimeIntegrity;
using UtoAegis.Infrastructure.Telemetry;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Guard;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var recover = args.Any(argument =>
            string.Equals(argument, "--recover", StringComparison.OrdinalIgnoreCase));
        var validateOnly = args.Any(argument =>
            string.Equals(argument, "--validate-config", StringComparison.OrdinalIgnoreCase));
        if (args.Any(argument =>
                !string.Equals(argument, "--recover", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(argument, "--validate-config", StringComparison.OrdinalIgnoreCase)) ||
            (recover && validateOnly))
        {
            Console.Error.WriteLine("Usage: utoaegis-guard [--recover | --validate-config]");
            return 2;
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("The UtoAegis integrity guard requires Windows.");
            return 2;
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        SecurityTelemetryWriter? telemetry = null;
        try
        {
            var configuration = GuardConfiguration.Load(
                Path.Combine(AppContext.BaseDirectory, "appsettings.json"),
                AppContext.BaseDirectory);
            var spool = new SecurityTelemetrySpool(
                configuration.SecurityTelemetrySpoolPath,
                new SecurityTelemetrySpoolOptions(configuration.TelemetryMaximumRecords));
            await spool.InitializeAsync(cancellation.Token);
            telemetry = new SecurityTelemetryWriter(
                spool,
                "guard",
                configuration.DeploymentId);

            var trustStore = await ThreatTrustStoreFileLoader.LoadAsync(
                configuration.TrustedSigningKeyPaths,
                cancellation.Token);
            var policy = await new SignedRuntimePolicyVerifier(trustStore)
                .VerifyAsync(configuration.PolicyBundlePath, cancellation.Token);
            if (validateOnly)
            {
                Console.WriteLine(
                    $"Configuration valid: policy={policy.Manifest.PolicyId}; " +
                    $"sequence={policy.Manifest.Sequence}; services={policy.Manifest.Services.Count}; " +
                    $"paths={policy.Manifest.Paths.Count}.");
                return 0;
            }

            await new RuntimePolicyStateStore(configuration.PolicyStatePath)
                .AcceptAsync(policy, cancellation.Token);
            var engine = new RuntimeIntegrityGuardEngine(
                new WindowsRuntimeIntegrityPlatform(),
                new RuntimeRecoveryStateStore(configuration.RecoveryStatePath));
            var result = await engine.RunAsync(
                policy.Manifest,
                recover,
                cancellation.Token);
            var correlationId = Guid.NewGuid().ToString("N");
            await telemetry.WriteAsync(
                "integrity.audit",
                correlationId,
                CreateTelemetryPayload(policy, result),
                cancellation.Token);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                policyId = policy.Manifest.PolicyId,
                policySequence = policy.Manifest.Sequence,
                healthy = result.IsHealthy,
                initialFindingCount = result.InitialFindings.Count,
                remainingFindingCount = result.RemainingFindings.Count,
                result.RecoveryRequested,
                result.RecoveryAttempted,
                result.RecoveryRateLimited,
                findings = result.RemainingFindings
            }));
            return result.IsHealthy ? 0 : 3;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            Console.Error.WriteLine("Integrity guard cancelled.");
            return 4;
        }
        catch (Exception exception) when (
            exception is GuardConfigurationException or RuntimePolicyException or
                ThreatUpdateException or SecurityTelemetryException or
                IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            if (telemetry is not null)
            {
                try
                {
                    await telemetry.WriteAsync(
                        "integrity.guardFailed",
                        Guid.NewGuid().ToString("N"),
                        new
                        {
                            errorType = exception.GetType().Name,
                            message = exception.Message
                        },
                        CancellationToken.None);
                }
                catch (SecurityTelemetryException)
                {
                }
            }

            Console.Error.WriteLine($"Integrity guard error: {exception.Message}");
            return 4;
        }
        finally
        {
            telemetry?.Dispose();
        }
    }

    private static object CreateTelemetryPayload(
        VerifiedRuntimePolicy policy,
        RuntimeIntegrityGuardResult result) =>
        new
        {
            policyId = policy.Manifest.PolicyId,
            policySequence = policy.Manifest.Sequence,
            policyManifestSha256 = policy.ManifestSha256,
            healthy = result.IsHealthy,
            initialFindingCount = result.InitialFindings.Count,
            remainingFindingCount = result.RemainingFindings.Count,
            result.RecoveryRequested,
            result.RecoveryAttempted,
            result.RecoveryRateLimited,
            findingsTruncated = result.RemainingFindings.Count > 24,
            findings = result.RemainingFindings.Take(24).Select(finding => new
            {
                kind = finding.Kind.ToString(),
                finding.Target,
                finding.Expected,
                finding.Actual,
                finding.Recoverable,
                finding.Message
            }).ToArray()
        };
}
