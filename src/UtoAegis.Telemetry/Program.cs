using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using UtoAegis.Infrastructure.Telemetry;

namespace UtoAegis.Telemetry;

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

        var hostArguments = args.Where(argument =>
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
            options.ServiceName = "UtoAegisTelemetry";
        });

        TelemetryConfiguration configuration;
        try
        {
            configuration = TelemetryConfiguration.Load(
                builder.Configuration,
                AppContext.BaseDirectory);
            var key = TelemetryConfiguration.LoadAuthenticationKey(
                configuration.AuthenticationKeyPath);
            CryptographicOperations.ZeroMemory(key);
        }
        catch (TelemetryConfigurationException exception)
        {
            Console.Error.WriteLine($"Telemetry configuration error: {exception.Message}");
            return 2;
        }

        if (validateOnly)
        {
            Console.WriteLine(
                $"Telemetry configuration valid: collector={configuration.CollectorUri.Host}; " +
                $"sources={configuration.Sources.Count}; batch={configuration.BatchSize}.");
            return 0;
        }

        builder.Services.AddSingleton(configuration);
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(services =>
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                CheckCertificateRevocationList = true,
                UseCookies = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = configuration.RequestTimeout
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("UtoAegis-Telemetry/1.0");
            var key = TelemetryConfiguration.LoadAuthenticationKey(
                configuration.AuthenticationKeyPath);
            try
            {
                return new TelemetryCollectorClient(
                    client,
                    configuration.CollectorUri,
                    configuration.AuthenticationKeyId,
                    key,
                    services.GetRequiredService<TimeProvider>());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        });
        builder.Services.AddSingleton<TelemetryForwarderEngine>();
        builder.Services.AddHostedService<TelemetryWorker>();

        using var host = builder.Build();
        if (runOnce)
        {
            try
            {
                var results = await host.Services
                    .GetRequiredService<TelemetryForwarderEngine>()
                    .RunOnceAsync();
                Console.WriteLine(
                    $"Delivered {results.Sum(result => result.DeliveredRecords)} record(s) " +
                    $"from {results.Count} source(s).");
                return 0;
            }
            catch (Exception exception) when (
                exception is TelemetryCollectorException or
                    SecurityTelemetryException or IOException)
            {
                Console.Error.WriteLine($"Telemetry delivery failed: {exception.Message}");
                return 3;
            }
        }

        await host.RunAsync();
        return 0;
    }

    private static bool HasOption(IEnumerable<string> args, string option) =>
        args.Any(argument => string.Equals(argument, option, StringComparison.OrdinalIgnoreCase));
}
