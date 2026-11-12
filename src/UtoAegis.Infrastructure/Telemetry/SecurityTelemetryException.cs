namespace UtoAegis.Infrastructure.Telemetry;

public sealed class SecurityTelemetryException : Exception
{
    public SecurityTelemetryException(string message)
        : base(message)
    {
    }

    public SecurityTelemetryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
