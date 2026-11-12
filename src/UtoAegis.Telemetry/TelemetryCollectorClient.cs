using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UtoAegis.Infrastructure.Telemetry;

namespace UtoAegis.Telemetry;

public sealed class TelemetryCollectorClient : IDisposable
{
    private const int MaximumResponseBytes = 16 * 1024;
    private static readonly JsonSerializerOptions SerializerOptions =
        new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly Uri _collectorUri;
    private readonly string _keyId;
    private readonly byte[] _authenticationKey;
    private readonly TimeProvider _timeProvider;

    public TelemetryCollectorClient(
        HttpClient httpClient,
        Uri collectorUri,
        string keyId,
        ReadOnlySpan<byte> authenticationKey,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(collectorUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (!string.Equals(collectorUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The telemetry collector URI must use HTTPS.", nameof(collectorUri));
        }

        if (authenticationKey.Length is < 32 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(authenticationKey));
        }

        _httpClient = httpClient;
        _collectorUri = collectorUri;
        _keyId = keyId;
        _authenticationKey = authenticationKey.ToArray();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<TelemetryCollectorAcknowledgement> SendAsync(
        string sourceName,
        IReadOnlyList<SecurityTelemetryEnvelope> records,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceName);
        ArgumentNullException.ThrowIfNull(records);
        if (records.Count == 0)
        {
            throw new ArgumentException("A telemetry batch cannot be empty.", nameof(records));
        }

        var body = JsonSerializer.SerializeToUtf8Bytes(
            new TelemetryBatch(1, sourceName, records),
            SerializerOptions);
        var timestamp = _timeProvider.GetUtcNow().ToUnixTimeSeconds()
            .ToString(CultureInfo.InvariantCulture);
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var bodyHash = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
        var pathAndQuery = _collectorUri.GetComponents(
            UriComponents.PathAndQuery,
            UriFormat.UriEscaped);
        var signingInput = Encoding.UTF8.GetBytes(
            $"POST\n/{pathAndQuery.TrimStart('/')}\n{timestamp}\n{nonce}\n{bodyHash}");
        var signature = Convert.ToBase64String(
            HMACSHA256.HashData(_authenticationKey, signingInput));

        using var request = new HttpRequestMessage(HttpMethod.Post, _collectorUri)
        {
            Content = new ByteArrayContent(body)
        };
        request.Content.Headers.ContentType = new("application/json");
        request.Headers.Add("X-UtoAegis-Key-Id", _keyId);
        request.Headers.Add("X-UtoAegis-Timestamp", timestamp);
        request.Headers.Add("X-UtoAegis-Nonce", nonce);
        request.Headers.Add("X-UtoAegis-Signature", signature);

        try
        {
            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new TelemetryCollectorException(
                    $"The telemetry collector returned HTTP {(int)response.StatusCode}.");
            }

            var length = response.Content.Headers.ContentLength;
            if (length is > MaximumResponseBytes)
            {
                throw new TelemetryCollectorException(
                    "The telemetry collector acknowledgement exceeds its size limit.");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            using var bounded = new MemoryStream();
            var buffer = new byte[4096];
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                if (bounded.Length + read > MaximumResponseBytes)
                {
                    throw new TelemetryCollectorException(
                        "The telemetry collector acknowledgement exceeds its size limit.");
                }

                await bounded.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
            }

            var acknowledgement = JsonSerializer.Deserialize<TelemetryCollectorAcknowledgement>(
                bounded.ToArray(),
                SerializerOptions) ?? throw new TelemetryCollectorException(
                    "The telemetry collector returned an empty acknowledgement.");
            if (acknowledgement.AcceptedSequence < 1 ||
                acknowledgement.AcceptedHash.Length != 64 ||
                acknowledgement.AcceptedHash.Any(character => !Uri.IsHexDigit(character)))
            {
                throw new TelemetryCollectorException(
                    "The telemetry collector acknowledgement is invalid.");
            }

            return acknowledgement;
        }
        catch (TelemetryCollectorException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException or JsonException or
                NotSupportedException)
        {
            throw new TelemetryCollectorException(
                "The authenticated telemetry delivery failed.",
                exception);
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_authenticationKey);
        _httpClient.Dispose();
    }

    private sealed record TelemetryBatch(
        int SchemaVersion,
        string Source,
        IReadOnlyList<SecurityTelemetryEnvelope> Records);
}
