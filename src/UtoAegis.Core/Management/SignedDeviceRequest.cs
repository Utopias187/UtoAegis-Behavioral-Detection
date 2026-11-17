namespace UtoAegis.Core.Management;

public sealed record SignedDeviceRequest
{
    public const int P1363SignatureLength = 64;

    public SignedDeviceRequest(DeviceRequestPayload payload, string signatureBase64)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureBase64);
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(signatureBase64);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "The device request signature must be base64 text.",
                nameof(signatureBase64),
                exception);
        }

        if (signature.Length != P1363SignatureLength)
        {
            throw new ArgumentException(
                $"The device request signature must contain {P1363SignatureLength} bytes.",
                nameof(signatureBase64));
        }

        Payload = payload;
        SignatureBase64 = Convert.ToBase64String(signature);
    }

    public DeviceRequestPayload Payload { get; }

    public string SignatureBase64 { get; }

    public byte[] GetSignatureBytes() => Convert.FromBase64String(SignatureBase64);
}
