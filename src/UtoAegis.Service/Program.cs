using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using UtoAegis.Infrastructure.RuntimeIntegrity;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var validateOnly = args.Any(argument =>
            string.Equals(argument, "--validate-config", StringComparison.OrdinalIgnoreCase));
        var hostArguments = args
            .Where(argument =>
                !string.Equals(argument, "--validate-config", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = hostArguments,
            ContentRootPath = AppContext.BaseDirectory
        });
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "UtoAegis";
        });

        ServiceConfiguration configuration;
        try
        {
            configuration = ServiceConfiguration.Load(
                builder.Configuration,
                AppContext.BaseDirectory);
        }
        catch (ServiceConfigurationException exception)
        {
            Console.Error.WriteLine($"Configuration error: {exception.Message}");
            return 2;
        }

        if (configuration.RuntimePolicyBundlePath is not null)
        {
            try
            {
                var trustStore = await ThreatTrustStoreFileLoader.LoadAsync(
                    configuration.TrustedRuntimePolicySigningKeyPaths);
                var verifiedPolicy = await new SignedRuntimePolicyVerifier(trustStore)
                    .VerifyAsync(configuration.RuntimePolicyBundlePath);
                configuration.ApplyAuthenticatedRuntimePolicy(verifiedPolicy);
                await new RuntimePolicyStateStore(configuration.RuntimePolicyStatePath!)
                    .AcceptAsync(verifiedPolicy);
            }
            catch (Exception exception) when (
                exception is RuntimePolicyException or ThreatUpdateException or
                    ServiceConfigurationException)
            {
                Console.Error.WriteLine($"Runtime-policy error: {exception.Message}");
                return 2;
            }
        }

        ServiceDetectionSources detectionSources;
        try
        {
            detectionSources = await ServiceDetectionSources.ResolveAsync(configuration);
        }
        catch (ThreatUpdateException exception)
        {
            Console.Error.WriteLine($"Threat-content error: {exception.Message}");
            return 2;
        }

        if (validateOnly)
        {
            Console.WriteLine(
                $"Configuration valid: monitor={configuration.MonitorRoot}; " +
                $"response={configuration.ResponsePolicy.Mode}; " +
                $"recursive={configuration.Recursive}; " +
                $"content={detectionSources.ContentVersion ?? "direct"}; " +
                $"policy={configuration.AuthenticatedRuntimePolicy?.Manifest.PolicyId ?? "local"}.");
            detectionSources.Dispose();
            return 0;
        }

        builder.Services.AddSingleton(configuration);
        builder.Services.AddSingleton(detectionSources);
        builder.Services.AddHostedService<ServiceWorker>();
        using var host = builder.Build();
        await host.RunAsync();
        return 0;
    }
}
