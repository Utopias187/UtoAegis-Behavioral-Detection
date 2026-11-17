namespace UtoAegis.Core.Management;

public sealed record BootstrapTokenConsumption(
    string TokenSha256,
    string DeviceId,
    RolloutRing RolloutRing,
    DateTimeOffset ConsumedUtc);
