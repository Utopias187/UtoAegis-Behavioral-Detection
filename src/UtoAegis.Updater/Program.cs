using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Updater;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var validateOnly = HasOption(args, "--validate-config");
        var runOnce = HasOption(args, "--once");
        if (validateOnly && runOnce)
        {
            Console.Error.WriteLine("Use either --validate-config or --once, not both.");
            return 2;
        }

        var hostArguments = args
            .Where(argument =>
                !string.Equals(argument, "--validate-config", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(argument, "--once", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = hostArguments,
            ContentRootPath = AppContext.BaseDirectory
        });
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "UtoAegisUpdater";
        });

        UpdaterConfiguration configuration;
        ThreatTrustStore trustStore;
        try
        {
            configuration = UpdaterConfiguration.Load(
                builder.Configuration,
                AppContext.BaseDirectory);
            trustStore = await ThreatTrustStoreFileLoader.LoadAsync(
                configuration.TrustedSigningKeyPaths);
        }
        catch (Exception exception) when (
            exception is UpdaterConfigurationException or ThreatUpdateException)
        {
            Console.Error.WriteLine($"Updater configuration error: {exception.Message}");
            return 2;
        }

        if (validateOnly)
        {
            Console.WriteLine(
                $"Updater configuration valid: channel={configuration.ChannelBaseUri.Host}; " +
                $"deployment={configuration.DeploymentId}; ring={configuration.RolloutRing}; " +
                $"trustedKeys={configuration.TrustedSigningKeyPaths.Count}; " +
                $"revokedKeys={configuration.RevokedSigningKeyIds.Count}.");
            return 0;
        }

        builder.Services.AddSingleton(configuration);
        builder.Services.AddSingleton(trustStore);
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(_ => new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            CheckCertificateRevocationList = true,
            UseCookies = false
        });
        builder.Services.AddSingleton(services =>
        {
            var client = new HttpClient(services.GetRequiredService<HttpClientHandler>())
            {
                Timeout = configuration.RequestTimeout
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("UtoAegis-Updater/1.0");
            return client;
        });
        builder.Services.AddSingleton(services => new SignedThreatBundleVerifier(
            services.GetRequiredService<ThreatTrustStore>(),
            timeProvider: services.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton(services => new ThreatContentStore(
            configuration.ContentStorePath,
            services.GetRequiredService<SignedThreatBundleVerifier>()));
        builder.Services.AddSingleton<IRemoteThreatBundleDownloader>(services =>
            new RemoteThreatBundleDownloader(
                services.GetRequiredService<HttpClient>(),
                services.GetRequiredService<SignedThreatBundleVerifier>()));
        builder.Services.AddSingleton(_ =>
            new UpdaterTelemetryWriter(configuration.TelemetryPath));
        builder.Services.AddSingleton<ThreatUpdaterEngine>();
        builder.Services.AddHostedService<UpdaterWorker>();

        using var host = builder.Build();
        if (runOnce)
        {
            try
            {
                var result = await host.Services
                    .GetRequiredService<ThreatUpdaterEngine>()
                    .RunOnceAsync();
                Console.WriteLine(
                    result.Status == UpdaterRunStatus.Activated
                        ? $"Activated threat content {result.Version} at sequence {result.Sequence}."
                        : $"Threat content sequence {result.Sequence} is already current.");
                return 0;
            }
            catch (Exception exception) when (
                exception is ThreatUpdateDownloadException or
                    ThreatUpdateSequenceException or ThreatUpdateException or IOException)
            {
                Console.Error.WriteLine($"Updater run failed: {exception.Message}");
                return 3;
            }
        }

        await host.RunAsync();
        return 0;
    }

    private static bool HasOption(IEnumerable<string> args, string option) =>
        args.Any(argument => string.Equals(argument, option, StringComparison.OrdinalIgnoreCase));
}
