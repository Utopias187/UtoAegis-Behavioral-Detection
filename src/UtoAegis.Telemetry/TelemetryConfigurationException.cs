namespace UtoAegis.Telemetry;

public sealed class TelemetryConfigurationException : Exception
{
    public TelemetryConfigurationException(string message)
        : base(message)
    {
    }

    public TelemetryConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
