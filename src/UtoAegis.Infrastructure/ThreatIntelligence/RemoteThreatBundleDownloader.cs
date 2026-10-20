using System.Net;
using UtoAegis.Core.ThreatIntelligence;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class RemoteThreatBundleDownloader
{
    private readonly HttpClient _httpClient;
    private readonly SignedThreatBundleVerifier _verifier;

    public RemoteThreatBundleDownloader(
        HttpClient httpClient,
        SignedThreatBundleVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(verifier);
        _httpClient = httpClient;
        _verifier = verifier;
    }

    public async ValueTask<DownloadedThreatBundle> DownloadAsync(
        Uri channelBaseUri,
        string downloadRoot,
        long highestAcceptedSequence,
        CancellationToken cancellationToken = default)
    {
        ValidateChannelUri(channelBaseUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(downloadRoot);
        ArgumentOutOfRangeException.ThrowIfNegative(highestAcceptedSequence);

        var rootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(downloadRoot));
        if (string.Equals(
                rootPath,
                Path.TrimEndingDirectorySeparator(Path.GetPathRoot(rootPath)!),
                PathComparison))
        {
            throw new ArgumentException(
                "The download root cannot be a filesystem root.",
                nameof(downloadRoot));
        }

        Directory.CreateDirectory(rootPath);
        EnsureRegularDirectory(rootPath);
        var bundlePath = Path.Combine(rootPath, $"download-{Guid.NewGuid():N}");
        Directory.CreateDirectory(bundlePath);

        try
        {
            await DownloadBoundedFileAsync(
                channelBaseUri,
                SignedThreatBundleVerifier.ManifestFileName,
                Path.Combine(bundlePath, SignedThreatBundleVerifier.ManifestFileName),
                ThreatManifestReader.MaximumManifestLength,
                expectedLength: null,
                cancellationToken).ConfigureAwait(false);
            await DownloadBoundedFileAsync(
                channelBaseUri,
                SignedThreatBundleVerifier.SignatureFileName,
                Path.Combine(bundlePath, SignedThreatBundleVerifier.SignatureFileName),
                SignedThreatBundleVerifier.MaximumSignatureTextLength,
                expectedLength: null,
                cancellationToken).ConfigureAwait(false);

            var manifest = await _verifier.VerifyManifestAsync(
                bundlePath,
                highestAcceptedSequence,
                cancellationToken).ConfigureAwait(false);
            foreach (var content in manifest.Contents)
            {
                await DownloadBoundedFileAsync(
                    channelBaseUri,
                    content.FileName,
                    Path.Combine(bundlePath, content.FileName),
                    content.Length,
                    content.Length,
                    cancellationToken).ConfigureAwait(false);
            }

            return new DownloadedThreatBundle(rootPath, bundlePath, manifest);
        }
        catch (OperationCanceledException)
        {
            DeleteOwnedDirectory(rootPath, bundlePath);
            throw;
        }
        catch
        {
            DeleteOwnedDirectory(rootPath, bundlePath);
            throw;
        }
    }

    public static void ValidateChannelUri(Uri channelBaseUri)
    {
        ArgumentNullException.ThrowIfNull(channelBaseUri);
        if (!channelBaseUri.IsAbsoluteUri ||
            !string.Equals(channelBaseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(channelBaseUri.Host) ||
            !string.IsNullOrEmpty(channelBaseUri.UserInfo) ||
            !string.IsNullOrEmpty(channelBaseUri.Query) ||
            !string.IsNullOrEmpty(channelBaseUri.Fragment) ||
            !channelBaseUri.AbsolutePath.EndsWith('/'))
        {
            throw new ArgumentException(
                "The update channel must be an absolute HTTPS directory URI without credentials, query, or fragment.",
                nameof(channelBaseUri));
        }
    }

    private async ValueTask DownloadBoundedFileAsync(
        Uri channelBaseUri,
        string fileName,
        string destinationPath,
        long maximumLength,
        long? expectedLength,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(channelBaseUri, fileName));
        request.Headers.AcceptEncoding.Clear();

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ThreatUpdateDownloadException(
                $"Downloading '{fileName}' timed out.",
                isTransient: true);
        }
        catch (HttpRequestException exception)
        {
            throw new ThreatUpdateDownloadException(
                $"Downloading '{fileName}' failed.",
                isTransient: true,
                exception.StatusCode,
                exception);
        }

        using (response)
        {
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new ThreatUpdateDownloadException(
                    $"Downloading '{fileName}' returned HTTP {(int)response.StatusCode}.",
                    IsTransient(response.StatusCode),
                    response.StatusCode);
            }

            var declaredLength = response.Content.Headers.ContentLength;
            if (declaredLength is <= 0 || declaredLength > maximumLength ||
                expectedLength.HasValue && declaredLength != expectedLength.Value)
            {
                throw new ThreatUpdateDownloadException(
                    $"The server declared an invalid length for '{fileName}'.",
                    isTransient: false,
                    response.StatusCode);
            }

            try
            {
                await using var source = await response.Content.ReadAsStreamAsync(cancellationToken)
                    .ConfigureAwait(false);
                await using var destination = new FileStream(
                    destinationPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 64 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                var buffer = new byte[64 * 1024];
                long total = 0;
                int bytesRead;
                while ((bytesRead = await source.ReadAsync(buffer, cancellationToken)
                    .ConfigureAwait(false)) != 0)
                {
                    total += bytesRead;
                    if (total > maximumLength || expectedLength.HasValue && total > expectedLength.Value)
                    {
                        throw new ThreatUpdateDownloadException(
                            $"The downloaded '{fileName}' exceeded its allowed length.",
                            isTransient: false,
                            response.StatusCode);
                    }

                    await destination.WriteAsync(
                        buffer.AsMemory(0, bytesRead),
                        cancellationToken).ConfigureAwait(false);
                }

                if (total == 0 || expectedLength.HasValue && total != expectedLength.Value ||
                    declaredLength.HasValue && total != declaredLength.Value)
                {
                    throw new ThreatUpdateDownloadException(
                        $"The downloaded '{fileName}' did not match its declared length.",
                        isTransient: false,
                        response.StatusCode);
                }

                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ThreatUpdateDownloadException)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new ThreatUpdateDownloadException(
                    $"The downloaded '{fileName}' could not be saved.",
                    isTransient: exception is IOException,
                    response.StatusCode,
                    exception);
            }
        }
    }

    private static bool IsTransient(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests ||
        (int)statusCode >= 500;

    private static void EnsureRegularDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new ThreatUpdateDownloadException(
                "The update download root must be a regular directory.",
                isTransient: false);
        }
    }

    private static void DeleteOwnedDirectory(string rootPath, string bundlePath)
    {
        if (!string.Equals(Path.GetDirectoryName(bundlePath), rootPath, PathComparison))
        {
            return;
        }

        try
        {
            if (Directory.Exists(bundlePath))
            {
                Directory.Delete(bundlePath, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
}
