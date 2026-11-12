namespace UtoAegis.Infrastructure.RuntimeIntegrity;

public sealed class RuntimePolicyException : Exception
{
    public RuntimePolicyException(string message)
        : base(message)
    {
    }

    public RuntimePolicyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
