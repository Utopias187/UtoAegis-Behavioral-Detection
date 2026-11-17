using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed record PolicyAcknowledgementState(
    PolicyAcknowledgement Acknowledgement,
    DateTimeOffset? DeliveredUtc)
{
    public bool IsPending => DeliveredUtc is null;
}
