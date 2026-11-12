namespace UtoAegis.Telemetry;

public sealed class TelemetryCollectorException : Exception
{
    public TelemetryCollectorException(string message)
        : base(message)
    {
    }

    public TelemetryCollectorException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
