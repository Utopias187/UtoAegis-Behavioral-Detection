namespace UtoAegis.Core.Management;

public sealed record SignedDeviceEnrollmentProof
{
    public SignedDeviceEnrollmentProof(
        DeviceEnrollmentProofPayload payload,
        string signatureBase64)
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
                "The enrollment proof signature must be base64 text.",
                nameof(signatureBase64),
                exception);
        }

        if (signature.Length != SignedDeviceRequest.P1363SignatureLength)
        {
            throw new ArgumentException(
                "The enrollment proof must contain a 64-byte P1363 signature.",
                nameof(signatureBase64));
        }

        Payload = payload;
        SignatureBase64 = Convert.ToBase64String(signature);
    }

    public DeviceEnrollmentProofPayload Payload { get; }

    public string SignatureBase64 { get; }

    public byte[] GetSignatureBytes() => Convert.FromBase64String(SignatureBase64);
}
