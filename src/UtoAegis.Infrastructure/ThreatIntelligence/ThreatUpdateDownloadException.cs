using System.Net;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class ThreatUpdateDownloadException : Exception
{
    public ThreatUpdateDownloadException(
        string message,
        bool isTransient,
        HttpStatusCode? statusCode = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        IsTransient = isTransient;
        StatusCode = statusCode;
    }

    public bool IsTransient { get; }

    public HttpStatusCode? StatusCode { get; }
}
