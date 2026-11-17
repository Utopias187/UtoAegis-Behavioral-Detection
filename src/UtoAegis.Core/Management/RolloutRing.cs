namespace UtoAegis.Core.Management;

public sealed record RolloutRing
{
    public RolloutRing(string value)
    {
        Value = DeviceIdentityState.ValidateIdentifier(value, 32, nameof(value));
    }

    public string Value { get; }

    public override string ToString() => Value;
}
