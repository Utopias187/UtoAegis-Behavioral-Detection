using System.Security.Cryptography;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceIdentityKeyContext : IDisposable
{
    internal DeviceIdentityKeyContext(DeviceIdentityState identity, ECDsa signingKey)
    {
        Identity = identity;
        SigningKey = signingKey;
    }

    public DeviceIdentityState Identity { get; }

    public ECDsa SigningKey { get; }

    public void Dispose() => SigningKey.Dispose();
}
