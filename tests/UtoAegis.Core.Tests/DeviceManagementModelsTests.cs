using System.Security.Cryptography;
using UtoAegis.Core.Management;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class DeviceManagementModelsTests
{
    [TestMethod]
    public void DeviceIdentityState_UppercaseHex_NormalizesIdentity()
    {
        var state = new DeviceIdentityState(
            new string('A', 32),
            "UtoAegis.Device.1",
            new string('B', 64),
            new DateTimeOffset(2026, 11, 17, 12, 0, 0, TimeSpan.Zero));

        Assert.AreEqual(new string('a', 32), state.DeviceId);
        Assert.AreEqual(new string('b', 64), state.PublicKeySha256);
    }

    [TestMethod]
    public void DeviceIdentityState_InvalidDeviceId_RejectsIdentity()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new DeviceIdentityState(
            "device-1",
            "UtoAegis.Device.1",
            new string('b', 64),
            DateTimeOffset.UtcNow));
    }

    [TestMethod]
    public void DeviceRequestPayload_MethodCase_ProducesSameCanonicalBytes()
    {
        var first = CreatePayload("post", "/v1/policy?current=7");
        var second = CreatePayload("POST", "/v1/policy?current=7");

        CollectionAssert.AreEqual(first.GetCanonicalBytes(), second.GetCanonicalBytes());
    }

    [TestMethod]
    public void DeviceRequestPayload_AbsoluteUri_RejectsTarget()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(() =>
            CreatePayload("POST", "https://management.example/v1/policy"));

        StringAssert.Contains(exception.Message, "absolute path");
    }

    [TestMethod]
    public void DeviceRequestPayload_Fragment_RejectsTarget()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            CreatePayload("POST", "/v1/policy#fragment"));
    }

    [TestMethod]
    public void SignedDeviceRequest_DerSignature_RejectsVariableLengthSignature()
    {
        var payload = CreatePayload("POST", "/v1/policy");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = key.SignData(
            payload.GetCanonicalBytes(),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        Assert.ThrowsExactly<ArgumentException>(() =>
            new SignedDeviceRequest(payload, Convert.ToBase64String(signature)));
    }

    private static DeviceRequestPayload CreatePayload(string method, string pathAndQuery) =>
        new(
            new string('a', 32),
            "enrollment-1",
            4,
            new DateTimeOffset(2026, 11, 17, 12, 0, 0, TimeSpan.Zero),
            new string('b', 32),
            method,
            pathAndQuery,
            new string('c', 64));
}
