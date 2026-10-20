namespace UtoAegis.Updater;

public sealed class UpdaterConfigurationException : Exception
{
    public UpdaterConfigurationException(string message)
        : base(message)
    {
    }

    public UpdaterConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
