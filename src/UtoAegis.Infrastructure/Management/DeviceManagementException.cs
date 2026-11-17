namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceManagementException : Exception
{
    public DeviceManagementException(string message)
        : base(message)
    {
    }

    public DeviceManagementException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
