namespace UtoAegis.Guard;

internal sealed class GuardConfigurationException : Exception
{
    public GuardConfigurationException(string message)
        : base(message)
    {
    }

    public GuardConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
